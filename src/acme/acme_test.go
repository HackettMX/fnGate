package acme

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fngate/cert"
	"fngate/core"
)

type harness struct {
	m     *Manager
	certs *cert.Manager
	store *core.Store
	dir   string
}

// newHarness 不启动后台 worker，便于对状态机做确定性断言。
func newHarness(t *testing.T, withWorker bool) *harness {
	t.Helper()
	dir := t.TempDir()
	bus := core.NewEventBus()
	log, err := core.NewLogger(dir, "ERROR")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	secrets := filepath.Join(dir, "secrets")
	certsDir := filepath.Join(dir, "certs")
	st, err := core.NewStore(filepath.Join(dir, "state.json"), secrets, bus)
	if err != nil {
		t.Fatal(err)
	}
	cm := cert.New(cert.Options{
		DataDir: dir, CertsDir: certsDir, SecretsDir: secrets,
		SysAllowedRoots: []string{dir}, Store: st, Bus: bus, Logger: log,
	})
	var m *Manager
	if withWorker {
		m = New(Deps{Store: st, Bus: bus, Logger: log, Certs: cm})
		t.Cleanup(func() { m.Close() })
	} else {
		m = &Manager{
			store: st, bus: bus, log: log, certs: cm,
			queue: make(chan string, 8), done: make(chan struct{}), runs: map[string]*runHandle{},
		}
	}
	return &harness{m: m, certs: cm, store: st, dir: dir}
}

func (h *harness) addManualProvider(t *testing.T) core.DNSProvider {
	t.Helper()
	p := core.DNSProvider{ID: "provider-manual", Type: "manual", Name: "手动 TXT", CreatedAt: nowText()}
	if err := h.store.Update(func(st *core.State) error {
		st.DNSProviders = append(st.DNSProviders, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNormalizeDomains(t *testing.T) {
	got, err := normalizeDomains([]string{"*.Example.COM.", "example.com", "example.com", "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("重复域名未去重：%v", got)
	}
	if got[0] != "example.com" {
		t.Fatalf("主域名应排首位：%v", got)
	}
	if got[2] != "*.example.com" {
		t.Fatalf("泛域名应排末尾：%v", got)
	}
	bad := [][]string{
		{""}, {"a b.com"}, {"*.*.example.com"}, {"localhost"}, {"http://example.com"}, {"-a.example.com"},
	}
	for _, b := range bad {
		if _, err := normalizeDomains(b); err == nil {
			t.Errorf("非法域名未被拒绝：%v", b)
		}
	}
}

func TestDirectoryURLPresets(t *testing.T) {
	if u, err := DirectoryURL(CALetsEncrypt, ""); err != nil || !strings.Contains(u, "letsencrypt.org") {
		t.Fatalf("生产 CA：%s %v", u, err)
	}
	if u, err := DirectoryURL(CAStaging, ""); err != nil || !strings.Contains(u, "staging") {
		t.Fatalf("Staging CA：%s %v", u, err)
	}
	if u, err := DirectoryURL(CAZeroSSL, ""); err != nil || !strings.Contains(u, "zerossl") {
		t.Fatalf("ZeroSSL CA：%s %v", u, err)
	}
	if u, err := DirectoryURL(CACustom, "https://acme.internal.example/dir"); err != nil || u != "https://acme.internal.example/dir" {
		t.Fatalf("自定义 CA：%s %v", u, err)
	}
	for _, bad := range []string{"", "ftp://x/dir", "not-a-url", "javascript:alert(1)"} {
		if _, err := DirectoryURL(CACustom, bad); err == nil {
			t.Errorf("非法 Directory 未被拒绝：%q", bad)
		}
	}
}

func TestProviderSpecsCoverRequiredProviders(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range ProviderSpecs() {
		seen[s.Type] = true
		for _, f := range s.Fields {
			if f.Key == "" || f.Label == "" {
				t.Fatalf("字段定义不完整：%+v", s)
			}
		}
	}
	for _, want := range []string{"alidns", "dnspod", "cloudflare", "manual"} {
		if !seen[want] {
			t.Fatalf("缺少 DNS 服务商 %s", want)
		}
	}
}

func TestBuildDNSManualAndMissingCredentials(t *testing.T) {
	h := newHarness(t, false)
	p := h.addManualProvider(t)
	b, err := h.m.buildDNS(p, "order-1", []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if b.manual == nil || len(b.opts) == 0 {
		t.Fatal("手动模式应返回 manualProvider 与预检选项")
	}
	// 凭据文件缺失时应给出可读错误，而不是 panic 或静默跳过。
	broken := core.DNSProvider{ID: "p2", Type: "alidns", Name: "阿里云", CredentialRef: dnsCredentialPath("p2")}
	if _, err := h.m.buildDNS(broken, "order-2", []string{"example.com"}); err == nil || !strings.Contains(err.Error(), "凭据") {
		t.Fatalf("缺失凭据应报错，实际 %v", err)
	}
}

func TestManualProviderRecordsTXT(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	h := newHarness(t, false)
	p := h.addManualProvider(t)
	o := core.ACMEOrder{
		ID: "order-txt", Domains: []string{"example.com", "*.example.com"},
		Status: "pending", Challenge: "dns-01", ProviderID: p.ID,
		Logs: []string{}, CreatedAt: nowText(), UpdatedAt: nowText(),
	}
	if err := h.store.Update(func(st *core.State) error {
		st.ACMEOrders = append(st.ACMEOrders, o)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b, err := h.m.buildDNS(p, o.ID, o.Domains)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.provider.Present("example.com", "token1", "keyAuth1"); err != nil {
		t.Fatal(err)
	}
	if err := b.provider.Present("example.com", "token2", "keyAuth2"); err != nil {
		t.Fatal(err)
	}
	updated, _ := h.m.order(o.ID)
	if len(updated.ManualTXT) != 2 {
		t.Fatalf("应登记两条 TXT 记录：%+v", updated.ManualTXT)
	}
	if updated.ManualTXT[0].Domain != "_acme-challenge.example.com" {
		t.Fatalf("TXT 记录名不对：%s", updated.ManualTXT[0].Domain)
	}
	if updated.ManualTXT[0].Value == updated.ManualTXT[1].Value {
		t.Fatal("同一 FQDN 的两条挑战记录值不应相同")
	}
	if updated.Status != "waiting_dns" {
		t.Fatalf("状态应变为 waiting_dns：%s", updated.Status)
	}
	if timeout, interval := b.provider.(*manualProvider).Timeout(); timeout != 30*time.Minute || interval != 10*time.Second {
		t.Fatal("手动模式应留足 DNS 传播等待时间")
	}
}

func TestBackoffAndHumanize(t *testing.T) {
	if backoff(1) != time.Hour || backoff(2) != 6*time.Hour || backoff(9) != 24*time.Hour {
		t.Fatal("失败退避应为 1h / 6h / 24h")
	}
	cases := map[string]string{
		"urn:ietf:params:acme:error:rateLimited": "速率限制",
		"Incorrect TXT record":                   "读不到预期的 TXT",
		"error presenting token":                 "写入 DNS TXT 记录失败",
		"dial tcp: connection refused":           "无法连接 ACME Directory",
	}
	for in, want := range cases {
		if got := humanizeACMEErr(errString(in)); !strings.Contains(got, want) {
			t.Errorf("humanizeACMEErr(%q)=%q 不含 %q", in, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRecoverStaleOrders(t *testing.T) {
	dir := t.TempDir()
	bus := core.NewEventBus()
	log, err := core.NewLogger(dir, "ERROR")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	secrets := filepath.Join(dir, "secrets")
	st, err := core.NewStore(filepath.Join(dir, "state.json"), secrets, bus)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *core.State) error {
		s.ACMEOrders = append(s.ACMEOrders, core.ACMEOrder{
			ID: "stale", Status: "validating", Domains: []string{"example.com"},
			ManualTXT: []core.TXTRecord{{Domain: "_acme-challenge.example.com", Value: "x"}},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cm := cert.New(cert.Options{DataDir: dir, CertsDir: filepath.Join(dir, "certs"), SecretsDir: secrets, Store: st, Bus: bus, Logger: log})
	m := New(Deps{Store: st, Bus: bus, Logger: log, Certs: cm})
	defer m.Close()
	o, _ := m.order("stale")
	if o.Status != "failed" || !strings.Contains(o.Error, "重启") {
		t.Fatalf("残留任务应标记为失败并提示重试：%+v", o)
	}
	if len(o.ManualTXT) != 0 {
		t.Fatal("残留的 TXT 记录应被清理")
	}
}

func TestCreateOrderValidation(t *testing.T) {
	h := newHarness(t, false)
	if _, err := h.m.CreateOrder(OrderPayload{Domains: []string{"bad host.com"}, ProviderID: "x"}); err == nil {
		t.Fatal("非法域名应被拒绝")
	}
	p := h.addManualProvider(t)
	if _, err := h.m.CreateOrder(OrderPayload{Domains: []string{"example.com"}, ProviderID: "missing"}); err == nil {
		t.Fatal("不存在的服务商应被拒绝")
	}
	o, err := h.m.CreateOrder(OrderPayload{
		Domains: []string{"*.example.com", "example.com"}, ProviderID: p.ID,
		CA: CALetsEncrypt, Email: "admin@example.com", AutoRenew: boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.Challenge != "dns-01" || o.KeyType != "ec256" || o.Status != "pending" {
		t.Fatalf("订单默认值不对：%+v", o)
	}
	if o.Domains[0] != "example.com" {
		t.Fatalf("主域名应排首位：%v", o.Domains)
	}
	st := h.store.Snapshot()
	if len(st.ACMEAccounts) != 1 {
		t.Fatalf("应隐式创建 ACME 账户：%d", len(st.ACMEAccounts))
	}
	if st.ACMEAccounts[0].Email != "admin@example.com" {
		t.Fatalf("账户邮箱未保存：%+v", st.ACMEAccounts[0])
	}
	if _, err := h.m.CreateOrder(OrderPayload{
		Domains: []string{"example.com"}, ProviderID: p.ID, CA: CACustom, DirectoryURL: "bad",
	}); err == nil || !strings.Contains(err.Error(), "http") {
		t.Fatalf("自定义 CA 的非法 URL 应被拒绝，实际 %v", err)
	}
}

func boolPtr(v bool) *bool { return &v }

func TestAutoRenewDecision(t *testing.T) {
	h := newHarness(t, false)
	// 把每日检查小时设为 0，避免测试在凌晨 3 点前跑时被时间窗口跳过。
	if err := h.store.Update(func(s *core.State) error {
		s.Settings.RenewHour = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := h.addManualProvider(t)
	cp, kp, err := cert.GenerateSelfSigned([]string{"renew.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	meta := &core.ACMEMeta{
		CA: CALetsEncrypt, Challenge: "dns-01", ProviderID: p.ID,
		AccountID: "acc", KeyType: "ec256", AutoRenew: true,
	}
	c, err := h.certs.AddACME("续期测试", cp, kp, meta)
	if err != nil {
		t.Fatal(err)
	}
	soon := time.Now().AddDate(0, 0, 10).UTC().Format(time.RFC3339)
	if err := h.certs.MutateCertificate(c.ID, func(x *core.Certificate) error {
		x.NotAfter = soon
		x.ACME.ProviderID = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h.m.tick()
	st := h.store.Snapshot()
	if len(st.ACMEOrders) != 1 {
		t.Fatalf("应自动排入 1 个续期任务，实际 %d", len(st.ACMEOrders))
	}
	if st.ACMEOrders[0].CertID != c.ID {
		t.Fatal("续期任务应绑定原 cert_id（保证零重启）")
	}
	updated, _ := h.certs.ByID(c.ID)
	if updated.ACME.NextRenewAt == "" {
		t.Fatal("应写入占位锁避免重复排队")
	}
	// 第二次 tick 不应重复排队。
	h.m.tick()
	if len(h.store.Snapshot().ACMEOrders) != 1 {
		t.Fatal("同一次到期周期内不应重复排队")
	}
}

func TestAPIConfigDoesNotLeakCredentials(t *testing.T) {
	h := newHarness(t, false)
	if err := h.store.SecretWrite(dnsCredentialPath("secret-provider"), []byte(`{"access_key":"TOPSECRET","secret_key":"ALSOSECRET"}`)); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Update(func(st *core.State) error {
		st.DNSProviders = append(st.DNSProviders, core.DNSProvider{
			ID: "secret-provider", Type: "alidns", Name: "阿里云",
			CredentialRef: dnsCredentialPath("secret-provider"), CreatedAt: nowText(),
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a := NewModule(h.m)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("overview 返回 %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "TOPSECRET") || strings.Contains(rec.Body.String(), "ALSOSECRET") {
		t.Fatal("API 响应泄露了 DNS 凭据")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["ok"] != true {
		t.Fatalf("响应格式不对：%s", rec.Body.String()[:200])
	}
}

// 编译期断言：证书模块必须始终满足反向代理的 CertResolver 契约。
var _ interface {
	Get(string, string) (*tls.Certificate, error)
	Fallback(string) (*tls.Certificate, error)
} = (*cert.Manager)(nil)
