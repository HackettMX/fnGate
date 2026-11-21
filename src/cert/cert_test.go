package cert

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fngate/core"
)

func newTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	bus := core.NewEventBus()
	log, err := core.NewLogger(dir, "ERROR")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	certsDir := filepath.Join(dir, "certs")
	secretsDir := filepath.Join(dir, "secrets")
	st, err := core.NewStore(filepath.Join(dir, "state.json"), secretsDir, bus)
	if err != nil {
		t.Fatal(err)
	}
	m := New(Options{
		DataDir: dir, CertsDir: certsDir, SecretsDir: secretsDir,
		SysConfPaths: []string{}, SysSSLRoots: []string{}, SysAllowedRoots: []string{dir},
		Store: st, Bus: bus, Logger: log,
	})
	return m, dir
}

func selfSignedPEM(t *testing.T, domains []string) ([]byte, []byte) {
	t.Helper()
	c, k, err := GenerateSelfSigned(domains)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func TestInspectParsesMetadata(t *testing.T) {
	cp, kp := selfSignedPEM(t, []string{"example.com", "*.example.com", "192.168.1.10"})
	d, err := Inspect(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if d.PrimaryDomain != "example.com" {
		t.Fatalf("主域名应取非泛域名项，实际 %q", d.PrimaryDomain)
	}
	if !d.Wildcard {
		t.Fatal("未识别泛域名")
	}
	if len(d.SANs) != 2 { // IP 走 IPAddresses SAN，不计入 DNSNames
		t.Fatalf("DNS SAN 数量不对: %v", d.SANs)
	}
	if _, err := time.Parse(time.RFC3339, d.NotAfter); err != nil {
		t.Fatalf("到期时间不是 RFC3339: %q", d.NotAfter)
	}
	if d.KeyType != "ECDSA P-256" {
		t.Fatalf("密钥类型识别错误: %s", d.KeyType)
	}
	if len(d.Fingerprint) != 64 {
		t.Fatal("指纹应为 SHA-256 十六进制")
	}
}

func TestInspectRejectsMismatchedKey(t *testing.T) {
	cp, _ := selfSignedPEM(t, []string{"a.example.com"})
	_, kp := selfSignedPEM(t, []string{"b.example.com"})
	if _, err := Inspect(cp, kp); err == nil {
		t.Fatal("不配套的私钥必须被拒绝")
	} else if !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("错误提示应可读，实际：%v", err)
	}
}

func TestMatchDomainRules(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"", "anything.test", true},
		{"a.example.com", "A.EXAMPLE.COM.", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
	}
	for _, c := range cases {
		if got := MatchDomain(c.pattern, c.host); got != c.want {
			t.Errorf("MatchDomain(%q,%q)=%v", c.pattern, c.host, got)
		}
	}
}

func TestUploadResolveByIDAndSNI(t *testing.T) {
	m, _ := newTestManager(t)
	cp, kp := selfSignedPEM(t, []string{"nas.example.com", "*.example.com"})
	c, err := m.AddManual("NAS 证书", cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != "manual" || c.CertPath == "" || c.KeyPath == "" {
		t.Fatalf("证书元数据异常: %+v", c)
	}
	if _, err := m.AddManual("重复上传", cp, kp); err == nil {
		t.Fatal("重复指纹应被拒绝")
	}
	got, err := m.Get(c.ID, "nas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("Get 未返回证书")
	}
	fb, err := m.Fallback("sub.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseLeaf(t, fb)
	if leaf == nil || len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "nas.example.com" {
		t.Fatalf("SNI 泛域名回退未命中正确证书: %v", leaf)
	}
	if err := m.SetDefault(c.ID); err != nil {
		t.Fatal(err)
	}
	if d, err := m.Fallback("unrelated.test"); err != nil || parseLeaf(t, d) == nil {
		t.Fatal("默认证书应在无匹配域名时生效")
	}
}

func TestRenewalTakesEffectWithoutRestart(t *testing.T) {
	m, _ := newTestManager(t)
	cp, kp := selfSignedPEM(t, []string{"old.example.com"})
	c, err := m.AddManual("站点证书", cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.Get(c.ID, "old.example.com")
	if err != nil {
		t.Fatal(err)
	}
	firstCN := parseLeaf(t, first).Subject.CommonName

	newCP, newKP := selfSignedPEM(t, []string{"renewed.example.com"})
	if _, err := m.ReplacePair(c.ID, newCP, newKP, false); err != nil {
		t.Fatal(err)
	}
	// 同一纳秒内落盘可能被 mtime 缓存判定为未变化，显式推进文件时间。
	bump := time.Now().Add(2 * time.Second)
	now := time.Now()
	updated, err := m.Get(c.ID, "renewed.example.com")
	if err != nil {
		t.Fatal(err)
	}
	updatedCN := parseLeaf(t, updated).Subject.CommonName
	if updatedCN == firstCN {
		if _, statErr := os.Stat(filepath.Join(m.CertsDir(), c.ID, "fullchain.pem")); statErr != nil {
			t.Fatal(statErr)
		}
		_ = os.Chtimes(filepath.Join(m.CertsDir(), c.ID, "fullchain.pem"), bump, bump)
		_ = os.Chtimes(filepath.Join(m.SecretsDir(), "certs", c.ID, "privkey.pem"), bump, bump)
		updated, err = m.Get(c.ID, "renewed.example.com")
		if err != nil {
			t.Fatal(err)
		}
		updatedCN = parseLeaf(t, updated).Subject.CommonName
	}
	if updatedCN != "renewed.example.com" {
		t.Fatalf("续期后握手未拿到新证书: %s (首次 %s, now=%v)", updatedCN, firstCN, now)
	}
	if _, ok := m.ByID(c.ID); !ok {
		t.Fatal("续期后 cert_id 应保持不变")
	}
}

func TestDeleteBlockedByReferences(t *testing.T) {
	m, _ := newTestManager(t)
	cp, kp := selfSignedPEM(t, []string{"used.example.com"})
	c, err := m.AddManual("在用证书", cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Store().Update(func(st *core.State) error {
		st.Listeners = append(st.Listeners, core.Listener{
			ID: "l1", Name: "HTTPS 443", Port: 443, Protocol: "https", Bind: "0.0.0.0",
			TLS: core.TLSConfig{CertID: c.ID}, Enabled: true,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err = m.Delete(c.ID)
	if err == nil || !strings.Contains(err.Error(), "被 1 处引用") {
		t.Fatalf("删除被引用证书应被阻断，实际：%v", err)
	}
	if err := m.Store().Update(func(st *core.State) error {
		st.Listeners = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(c.ID); err != nil {
		t.Fatalf("解除引用后应可删除：%v", err)
	}
	if _, ok := m.ByID(c.ID); ok {
		t.Fatal("删除后仍有元数据")
	}
}

func TestSyncSystemImportsFnosSnapshot(t *testing.T) {
	m, dir := newTestManager(t)
	cp, kp := selfSignedPEM(t, []string{"fn.example.com"})
	sysDir := filepath.Join(dir, "fake-trim", "etc")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certSrc := filepath.Join(sysDir, "fn.example.com.crt")
	keySrc := filepath.Join(sysDir, "fn.example.com.key")
	if err := os.WriteFile(certSrc, cp, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keySrc, kp, 0o600); err != nil {
		t.Fatal(err)
	}
	conf := map[string]interface{}{
		"certs": []map[string]string{{
			"host": "fn.example.com", "cert": certSrc, "key": keySrc,
		}},
	}
	confRaw, _ := json.Marshal(conf)
	confPath := filepath.Join(sysDir, "network_cert_all.conf")
	if err := os.WriteFile(confPath, confRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	m.opt.SysConfPaths = []string{confPath}
	m.opt.SysAllowedRoots = []string{sysDir}

	res, err := SyncSystem(SyncOptions{
		DataDir: dir, CertsDir: m.CertsDir(), SecretsDir: m.SecretsDir(),
		ConfPaths: []string{confPath}, SSLRoots: []string{},
		AllowedRoots: []string{sysDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 1 {
		t.Fatalf("应写入 1 张飞牛证书，实际 %d warnings=%v", res.Written, res.Warnings)
	}
	imported, err := m.ImportFromSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if imported["imported"].(int) != 1 {
		t.Fatalf("导入数量不对：%v", imported)
	}
	st := m.Store().Snapshot()
	if len(st.Certificates) != 1 || st.Certificates[0].Source != "fnos" {
		t.Fatalf("飞牛证书未登记：%+v", st.Certificates)
	}
	if !strings.HasPrefix(st.Certificates[0].Name, "飞牛证书") {
		t.Fatalf("来源标识缺失：%s", st.Certificates[0].Name)
	}
	// 再同步一次应只更新不新增。
	if _, err := m.ImportFromSnapshot(); err != nil {
		t.Fatal(err)
	}
	if len(m.Store().Snapshot().Certificates) != 1 {
		t.Fatal("重复同步产生了重复证书")
	}
	// 私钥文件权限必须是 0600。
	info, err := os.Stat(filepath.Join(m.SecretsDir(), "certs", st.Certificates[0].ID, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows 的 os.Chmod 只映射只读位，无法表达 0600；
	// 生产环境是 Linux（.fpk 只跑在 fnOS 上），这里仅在非 Windows 断言权限。
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("私钥权限过宽：%v", info.Mode().Perm())
	}
}

func TestSyncSystemRejectsPathOutsideAllowlist(t *testing.T) {
	m, dir := newTestManager(t)
	cp, kp := selfSignedPEM(t, []string{"evil.example.com"})
	sysDir := filepath.Join(dir, "fake-trim", "etc")
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	certSrc := filepath.Join(outside, "evil.crt")
	keySrc := filepath.Join(outside, "evil.key")
	_ = os.WriteFile(certSrc, cp, 0o644)
	_ = os.WriteFile(keySrc, kp, 0o600)
	confRaw, _ := json.Marshal([]map[string]string{{
		"host": "evil.example.com", "cert": certSrc, "key": keySrc,
	}})
	confPath := filepath.Join(sysDir, "network_cert_all.conf")
	_ = os.WriteFile(confPath, confRaw, 0o644)
	res, err := SyncSystem(SyncOptions{
		DataDir: dir, CertsDir: m.CertsDir(), SecretsDir: m.SecretsDir(),
		ConfPaths: []string{confPath}, AllowedRoots: []string{sysDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 0 || res.Skipped != 1 {
		t.Fatalf("白名单外的路径应被拒绝：%+v", res)
	}
	if len(m.Store().Snapshot().Certificates) != 0 {
		t.Fatal("不应导入任何证书")
	}
}

func TestSyncDoesNotEraseExistingSnapshot(t *testing.T) {
	m, dir := newTestManager(t)
	cp, kp := selfSignedPEM(t, []string{"keep.example.com"})
	sysDir := filepath.Join(dir, "fake-trim", "etc")
	_ = os.MkdirAll(sysDir, 0o755)
	certSrc := filepath.Join(sysDir, "keep.crt")
	keySrc := filepath.Join(sysDir, "keep.key")
	_ = os.WriteFile(certSrc, cp, 0o644)
	_ = os.WriteFile(keySrc, kp, 0o600)
	confRaw, _ := json.Marshal([]map[string]string{{
		"host": "keep.example.com", "cert": certSrc, "key": keySrc,
	}})
	confPath := filepath.Join(sysDir, "network_cert_all.conf")
	_ = os.WriteFile(confPath, confRaw, 0o644)
	opts := SyncOptions{
		DataDir: dir, CertsDir: m.CertsDir(), SecretsDir: m.SecretsDir(),
		AllowedRoots: []string{sysDir},
	}
	opts.ConfPaths = []string{confPath}
	if _, err := SyncSystem(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ImportFromSnapshot(); err != nil {
		t.Fatal(err)
	}
	// 模拟降权进程读不到系统证书：一次空同步不能把已有快照清空。
	opts.ConfPaths = nil
	opts.SSLRoots = nil
	res, err := SyncSystem(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Written != 0 {
		t.Fatal("无来源时不应写入证书")
	}
	if _, count := m.SnapshotInfo(); count != 1 {
		t.Fatalf("已有快照被空同步覆盖，count=%d", count)
	}
	if _, err := m.ImportFromSnapshot(); err != nil {
		t.Fatal(err)
	}
	if len(m.Store().Snapshot().Certificates) != 1 {
		t.Fatal("证书被误删")
	}
}

func parseLeaf(t *testing.T, c *tls.Certificate) *x509.Certificate {
	t.Helper()
	if c == nil || len(c.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// 「导出证书包」必须把证书链和私钥一起给到（飞牛系统证书要求 crt + key），
// 且两者要能配成一对——否则用户导入后才在浏览器里发现握手失败。
func TestExportBundleContainsPairedCertAndKey(t *testing.T) {
	m, _ := newTestManager(t)
	c, err := m.AddSelfSigned("导出测试", []string{"bundle.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/"+c.ID+"/export", nil)
	rec := httptest.NewRecorder()
	NewModule(m).Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type 应为 application/zip，实际 %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "bundle.example.com.zip") {
		t.Fatalf("文件名应基于主域名，实际 %q", cd)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("证书包不允许被缓存")
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("返回的不是合法 ZIP：%v", err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = data
	}
	for _, want := range []string{"fullchain.pem", "privkey.pem", "README.txt"} {
		if len(files[want]) == 0 {
			t.Fatalf("压缩包缺少 %s", want)
		}
	}
	if !strings.Contains(string(files["fullchain.pem"]), "BEGIN CERTIFICATE") {
		t.Fatal("fullchain.pem 不是 PEM 证书")
	}
	if !strings.Contains(string(files["privkey.pem"]), "PRIVATE KEY") {
		t.Fatal("privkey.pem 不是 PEM 私钥")
	}
	// 私钥与证书必须配套，否则导入飞牛后 HTTPS 起不来。
	if _, err := tls.X509KeyPair(files["fullchain.pem"], files["privkey.pem"]); err != nil {
		t.Fatalf("导出的证书与私钥不匹配：%v", err)
	}
	if !strings.Contains(string(files["README.txt"]), "bundle.example.com") {
		t.Fatal("说明文件里应写明域名")
	}
}

// 没有本机私钥的证书（例如只导入了证书链）必须明确拒绝，不能给个残缺包。
func TestExportBundleRejectsCertWithoutKey(t *testing.T) {
	m, _ := newTestManager(t)
	c, err := m.AddSelfSigned("无钥匙", []string{"nokey.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MutateCertificate(c.ID, func(x *core.Certificate) error {
		x.KeyPath = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/"+c.ID+"/export", nil)
	rec := httptest.NewRecorder()
	NewModule(m).Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "没有本机私钥") {
		t.Fatalf("错误信息应说明原因，实际 %s", rec.Body.String())
	}
}

// GET 只给证书链，私钥不能从这条路出去。
func TestDownloadNeverReturnsPrivateKey(t *testing.T) {
	m, _ := newTestManager(t)
	c, err := m.AddSelfSigned("下载", []string{"dl.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/"+c.ID+"/download", nil)
	rec := httptest.NewRecorder()
	NewModule(m).Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("GET /download 泄漏了私钥")
	}
}
