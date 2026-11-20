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
	id, ok := before["id"].(json.Number)
	if !ok {
		return fail(CodeIncompatible)
	}
	idInt, err := strconv.ParseInt(id.String(), 10, 64)
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

// regular 校验文件安全属性：普通文件、非软链、nlink==1、大小受限、路径在 certRoot 下、
// 且从文件到根的每一级属主为 root 且无 group/other 写位。
func (e *Engine) regular(file string, isCert bool) (os.FileInfo, error) {
	st, err := os.Lstat(file)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return nil, fail(CodeIncompatible)
	}
	if fileNlink(st) != 1 {
		return nil, fail(CodeIncompatible)
	}
	if isCert {
		rel, err := filepath.Rel(e.CertRoot, file)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return nil, fail(CodeIncompatible)
		}
		realFile, err1 := filepath.EvalSymlinks(file)
		realRoot, err2 := filepath.EvalSymlinks(e.CertRoot)
		if err1 != nil || err2 != nil || realFile != filepath.Join(realRoot, rel) {
			return nil, fail(CodeIncompatible)
		}
	}
	if e.Secure {
		cur, err := filepath.EvalSymlinks(file)
		if err != nil {
			return nil, fail(CodeIncompatible)
		}
		for {
			info, err := os.Stat(cur)
			if err != nil || !ownedByRootNotWritable(info) {
				return nil, fail(CodeIncompatible)
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}
	return st, nil
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

func probeTLS(host string, port int, fingerprint string, requireTrust bool) error {
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !requireTrust, // 部署前用证书 pin 校验，部署后再叠加公共信任
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 7 * time.Second}, "tcp", loopbackAddr(port), cfg)
	if err != nil {
		return fail(CodeTLS)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fail(CodeTLS)
	}
	if !sameFingerprint(fingerprint256(certs[0].Raw), fingerprint) {
		return fail(CodeTLS)
	}
	return nil
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
