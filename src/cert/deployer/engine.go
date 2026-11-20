package deployer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// nowFunc / rootCAs 便于测试替换。
var (
	nowFunc = time.Now
	rootCAs = func() (*x509.CertPool, error) { return x509.SystemCertPool() }
)

// ---------- 子进程执行 ----------

const cmdTimeout = 20 * time.Second
const restartTimeout = 30 * time.Second

// command 在受限环境下执行命令，SQL/输入走 stdin，输出上限 4 MiB。
func command(file string, args []string, input string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, file, args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"PGCONNECT_TIMEOUT=5",
	}
	cmd.Stdin = strings.NewReader(input)
	var out strings.Builder
	cmd.Stdout = &limitWriter{buf: &out, max: 4 << 20}
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fail(CodeIncompatible)
	}
	return strings.TrimSpace(out.String()), nil
}

// limitWriter 限制捕获的输出大小，超过上限写失败会导致命令退出非零。
type limitWriter struct {
	buf *strings.Builder
	max int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if lw.buf.Len()+len(p) > lw.max {
		return 0, fmt.Errorf("output too large")
	}
	return lw.buf.Write(p)
}

// psql 以 postgres 用户连接 trim_connect，SQL 走 stdin。
func psql(sql string) (string, error) {
	return command("/usr/sbin/runuser",
		[]string{"-u", "postgres", "--", "/usr/bin/psql",
			"-d", DBName, "-XqAt", "-v", "ON_ERROR_STOP=1"},
		sql, cmdTimeout)
}

// sqlJSON 把值编码成 SQL 里的 jsonb 字面量（base64 传递避免转义注入）。
func sqlJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	encoded := base64.StdEncoding.EncodeToString(b)
	return fmt.Sprintf("convert_from(decode('%s','base64'),'UTF8')::jsonb", encoded)
}

// compareAndSwapRow 用整行 JSON 相等作为 CAS 条件更新证书元数据，防止并发冲突。
func compareAndSwapRow(before, after map[string]interface{}) error {
	idText := rowString(certRow(before), "id")
	idInt, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || idInt <= 0 {
		return fail(CodeIncompatible)
	}
	if canonicalJSON(before["id"]) != canonicalJSON(after["id"]) {
		return fail(CodeIncompatible)
	}
	fields := []string{"valid_from", "valid_to", "encrypt_type", "issued_by", "status", "updated_time"}
	assign := []string{}
	for _, f := range fields {
		assign = append(assign, fmt.Sprintf("%s=v.%s", f, f))
	}
	sql := fmt.Sprintf(
		"BEGIN; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='8s'; "+
			"WITH v AS (SELECT * FROM jsonb_populate_record(NULL::public.cert,%s)), "+
			"changed AS (UPDATE public.cert c SET %s FROM v WHERE c.id=%d AND to_jsonb(c)=%s RETURNING 1) "+
			"SELECT CASE WHEN count(*)=1 THEN 1 ELSE (count(*)::text || ' conflict')::integer END FROM changed; COMMIT;",
		sqlJSON(after), strings.Join(assign, ","), idInt, sqlJSON(before))
	res, err := psql(sql)
	if err != nil || strings.TrimSpace(res) != "1" {
		return fail(CodeConflict)
	}
	return nil
}

// ---------- 文件安全 ----------

// 文件检查分两层：
//
//  1. 硬性拒绝（fail-closed）：非普通文件、软链接、多硬链接、超大、文件自身对其他用户
//     可写、证书路径（解析软链后）不在 CertRoot 下、文件所在目录对其他用户可写。
//     真正的劫持面只有「文件自身」与「它所在的目录」，这两处保持严格。
//  2. 仅记录进诊断、不阻断：祖先目录权限、目录属主是 fnOS 服务账号、组写位（0775 root:trim
//     这类布局在真机上很常见，把组写位一律当成攻击面会让功能完全不可用）。
//
// 写盘一律走「临时文件 + rename」，不会跟随目标路径上的软链（会整体替换该名字），
// 因此软链替换攻击不会把内容写到别处。任何不符合项都写进 detail，便于真机直接读出原因。

// regular 校验文件安全属性，返回 Lstat 结果；不通过时错误里带逐项事实。
func (e *Engine) regular(file string, isCert bool) (os.FileInfo, error) {
	st, blocking, _ := e.pathFacts(file, isCert)
	if len(blocking) > 0 {
		return nil, failDetail(CodeIncompatible, "path", file+"："+strings.Join(blocking, "；"))
	}
	return st, nil
}

// pathFacts 逐项列出路径不符合安全条件的事实。
// blocking 中任意一项非空即视为不可写；notes 只是提示，不影响结果。
func (e *Engine) pathFacts(file string, isCert bool) (os.FileInfo, []string, []string) {
	st, err := os.Lstat(file)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return nil, []string{"路径不存在（可能 fnOS 版本改动了存放位置）"}, nil
		case os.IsPermission(err):
			return nil, []string{"部署服务无权访问该路径"}, nil
		default:
			return nil, []string{"无法读取路径属性：" + err.Error()}, nil
		}
	}
	var blocking, notes []string
	if st.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(file)
		blocking = append(blocking, fmt.Sprintf("是软链接（→ %s），要求普通文件", target))
	} else if !st.Mode().IsRegular() {
		blocking = append(blocking, fmt.Sprintf("不是普通文件（%s）", modeTypeText(st.Mode())))
	} else {
		if st.Size() > 4<<20 {
			blocking = append(blocking, fmt.Sprintf("文件过大（%d 字节）", st.Size()))
		}
		if n := fileNlink(st); n != 1 {
			blocking = append(blocking, fmt.Sprintf("硬链接数为 %d，要求恰好 1", n))
		}
		if st.Mode().Perm()&0o002 != 0 {
			blocking = append(blocking, fmt.Sprintf("文件权限 %s 允许其他用户写入", st.Mode().Perm()))
		}
	}
	if isCert {
		blocking = append(blocking, e.rootFacts(file)...)
	}
	if e.Secure {
		b, n := e.dirFacts(file)
		blocking = append(blocking, b...)
		notes = append(notes, n...)
	}
	return st, blocking, notes
}

// rootFacts 校验路径（解析软链后）仍落在证书根目录内。
func (e *Engine) rootFacts(file string) []string {
	root := filepath.Clean(e.CertRoot)
	clean := filepath.Clean(file)
	if clean != root && !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return []string{fmt.Sprintf("不在证书根目录 %s 下（fnOS 版本可能改了证书存放位置）", root)}
	}
	realFile, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return []string{"无法解析真实路径：" + err.Error()}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return []string{fmt.Sprintf("无法解析证书根目录 %s：%v", root, err)}
	}
	rel, err := filepath.Rel(realRoot, realFile)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return []string{fmt.Sprintf("解析软链接后指向 %s，不在证书根目录 %s 下", realFile, realRoot)}
	}
	return nil
}

// dirFacts 校验文件所在目录：必须真实存在、不能被「其他用户」写入。
// 属主是 fnOS 自己的服务账号（例如 www-data）或组可写只作为提示——那些进程本来就
// 拥有这些证书文件，把它们当成攻击面只会让功能在真机上不可用。真正的越权面是
// 「任何本地用户都能写」的目录，这一条保持阻断。更高层祖先目录同样只提示。
func (e *Engine) dirFacts(file string) (blocking, notes []string) {
	real, err := filepath.EvalSymlinks(file)
	if err != nil {
		return []string{"无法解析真实路径：" + err.Error()}, nil
	}
	for cur, depth := filepath.Dir(real), 0; ; depth++ {
		info, err := os.Stat(cur)
		if err != nil {
			return append(blocking, fmt.Sprintf("目录 %s 不可访问：%v", cur, err)), notes
		}
		if !info.IsDir() {
			return append(blocking, fmt.Sprintf("%s 不是目录", cur)), notes
		}
		if desc, worldWritable := dirRisk(info); desc != "" {
			if depth == 0 && worldWritable {
				return append(blocking, fmt.Sprintf("所在目录 %s %s", cur, desc)), notes
			}
			notes = append(notes, fmt.Sprintf("目录 %s %s", cur, desc))
		}
		parent := filepath.Dir(cur)
		if parent == cur || len(notes) >= 3 {
			return blocking, notes
		}
		cur = parent
	}
}

// dirRisk 描述目录的可写风险；第二个返回值表示是否「其他用户可写」（唯一阻断项）。
func dirRisk(info os.FileInfo) (desc string, worldWritable bool) {
	perm := info.Mode().Perm()
	uid, gid := fileUID(info), fileGID(info)
	if perm&0o002 != 0 {
		return fmt.Sprintf("权限 %s 属主 %d:%d，其他用户可写", perm, uid, gid), true
	}
	if uid != 0 {
		return fmt.Sprintf("权限 %s 属主 %d:%d，非 root 所有（组写位不阻断）", perm, uid, gid), false
	}
	return "", false
}

// pathReport 生成一句可直接展示的路径诊断（含提示项），供 status 使用。
func (e *Engine) pathReport(file string, isCert bool) string {
	_, blocking, notes := e.pathFacts(file, isCert)
	parts := append(append([]string{}, blocking...), notes...)
	if len(parts) == 0 {
		return ""
	}
	return "文件 " + file + "：" + strings.Join(parts, "；")
}

func modeTypeText(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "软链接"
	case m.IsDir():
		return "目录"
	case m&os.ModeNamedPipe != 0:
		return "命名管道"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeDevice != 0:
		return "设备文件"
	default:
		return "特殊文件"
	}
}

func ownedByRootNotWritable(info os.FileInfo) bool {
	return fileUID(info) == 0 && info.Mode().Perm()&0o022 == 0
}

// snapshot 保存文件原始内容（base64）与权限信息，供回滚使用。
func (e *Engine) snapshot(file string, isCert bool) (*fileSnapshot, error) {
	st, err := e.regular(file, isCert)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fail(CodeIncompatible)
	}
	return &fileSnapshot{
		File:    file,
		Content: base64.StdEncoding.EncodeToString(data),
		Mode:    st.Mode().Perm(),
		IsCert:  isCert,
		UID:     ownerUID(st),
		GID:     ownerGID(st),
	}, nil
}

func ownerUID(info os.FileInfo) int { return fileUID(info) }
func ownerGID(info os.FileInfo) int { return fileGID(info) }

// atomic 原子写：临时文件 + fsync + rename + 目录 fsync，保持属主与权限。
func (e *Engine) atomic(file string, data []byte, mode os.FileMode, uid, gid int) error {
	tmp := fmt.Sprintf("%s.%s.tmp", file, newUUID())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fail(CodeIncompatible)
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fail(CodeIncompatible)
	}
	if e.Secure && uid >= 0 {
		if err := f.Chown(uid, gid); err != nil {
			return fail(CodeIncompatible)
		}
	}
	if err := f.Chmod(mode); err != nil {
		return fail(CodeIncompatible)
	}
	if err := f.Sync(); err != nil {
		return fail(CodeIncompatible)
	}
	if err := f.Close(); err != nil {
		return fail(CodeIncompatible)
	}
	if err := os.Rename(tmp, file); err != nil {
		return fail(CodeIncompatible)
	}
	ok = true
	if e.Secure {
		if dir, err := os.Open(filepath.Dir(file)); err == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
	}
	return nil
}

// replace 在再次校验文件安全后原子替换。
func (e *Engine) replace(s *fileSnapshot, data []byte, mode os.FileMode, gid int) error {
	if _, err := e.regular(s.File, s.IsCert); err != nil {
		return err
	}
	useMode := s.Mode
	if mode != 0 {
		useMode = mode
	}
	useGID := s.GID
	if gid > 0 {
		useGID = gid
	}
	return e.atomic(s.File, data, useMode, s.UID, useGID)
}

func sameContent(file string, a, b string) bool {
	if isConfigPath(file) {
		return equalJSON(b64JSON(a), b64JSON(b))
	}
	return a == b
}

func isConfigPath(file string) bool { return file == IndexPath || file == GatewayPath }

func b64JSON(s string) interface{} {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

// ---------- 探测与端口 ----------

// probeTLS 与本机 127.0.0.1:port 做一次 TLS 握手，校验返回的叶子证书指纹。
// 失败时带上可直接展示的原因（连接失败 / 指纹不符 / 不受信任），
// 避免真机上只看到「HTTPS 验证未通过」却不知道是端口填错还是证书没生效。
func probeTLS(host string, port int, fingerprint string, requireTrust bool) error {
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !requireTrust, // 部署前用证书 pin 校验，部署后再叠加公共信任
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 7 * time.Second}, "tcp", loopbackAddr(port), cfg)
	if err != nil {
		if requireTrust {
			return failDetail(CodeTLS, "trust",
				fmt.Sprintf("127.0.0.1:%d 的 TLS 握手或证书信任校验失败：%v", port, err))
		}
		return failDetail(CodeTLS, "connect",
			fmt.Sprintf("无法连接 127.0.0.1:%d（%v）；请填飞牛「系统设置 → 安全性 → 端口」里的 HTTPS 端口", port, err))
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return failDetail(CodeTLS, "cert", fmt.Sprintf("127.0.0.1:%d 未返回任何证书", port))
	}
	if !sameFingerprint(fingerprint256(certs[0].Raw), fingerprint) {
		return failDetail(CodeTLS, "fingerprint",
			fmt.Sprintf("127.0.0.1:%d 当前使用的证书指纹 %s… 与目标证书 %s… 不一致（该端口可能不是这张证书绑定的服务）",
				port, shortFP(fingerprint256(certs[0].Raw)), shortFP(fingerprint)))
	}
	return nil
}

// shortFP 取指纹前 17 个字符（AA:BB:... 形式）用于提示。
func shortFP(fp string) string {
	if len(fp) <= 17 {
		return fp
	}
	return fp[:17]
}

func detectPorts() []int {
	out, err := command("/usr/bin/ss", []string{"-H", "-ltnp"}, "", cmdTimeout)
	if err != nil {
		return nil
	}
	set := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `"nginx"`) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		p, err := strconv.Atoi(addr[i+1:])
		if err == nil && validPort(p) {
			set[p] = true
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	if len(ports) > 16 {
		ports = ports[:16]
	}
	return ports
}

func keyPermissions() (os.FileMode, int, error) {
	// 校验 nginx 配置为 root 所有且不可被 group/other 写。
	st, err := os.Lstat(NginxConf)
	if err != nil || !st.Mode().IsRegular() || !ownedByRootNotWritable(st) || st.Size() > 2<<20 {
		return 0, 0, fail(CodeIncompatible)
	}
	raw, err := os.ReadFile(NginxConf)
	if err != nil {
		return 0, 0, fail(CodeIncompatible)
	}
	if !verifyNginxUser(string(raw)) {
		return 0, 0, fail(CodeIncompatible)
	}
	gidOut, err := command("/usr/bin/id", []string{"-g", "www-data"}, "", cmdTimeout)
	if err != nil {
		return 0, 0, fail(CodeIncompatible)
	}
	gid, err := strconv.Atoi(strings.TrimSpace(gidOut))
	if err != nil || gid <= 0 {
		return 0, 0, fail(CodeIncompatible)
	}
	return 0o640, gid, nil
}

// verifyNginxUser 校验 nginx.conf 里唯一的 user 指令为 www-data（可带组）。
func verifyNginxUser(conf string) bool {
	var users [][]string
	for _, line := range strings.Split(conf, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "user ") && strings.HasSuffix(s, ";") {
			users = append(users, strings.Fields(strings.TrimSuffix(strings.TrimPrefix(s, "user "), ";")))
		}
	}
	if len(users) != 1 || len(users[0]) == 0 || users[0][0] != "www-data" || len(users[0]) > 2 {
		return false
	}
	if len(users[0]) == 2 && users[0][1] != "www-data" {
		return false
	}
	return true
}

func restartServices() error {
	for _, svc := range []string{"network_service.service", "trim_nginx.service"} {
		if _, err := command("/usr/bin/systemctl", []string{"restart", svc}, "", restartTimeout); err != nil {
			return fail(CodeIncompatible)
		}
		if _, err := command("/usr/bin/systemctl", []string{"is-active", "--quiet", svc}, "", cmdTimeout); err != nil {
			return fail(CodeIncompatible)
		}
	}
	return nil
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
