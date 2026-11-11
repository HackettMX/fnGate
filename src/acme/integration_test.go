package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fngate/core"
)

// fakeCA 是一个最小但足够真实的 ACME v2 服务端：
// 目录 / nonce / 账户 / 订单 / 授权 / DNS-01 challenge / finalize / 证书下载。
// 它不校验 JWS 签名（测试关注 fnGate 的编排），但完整遵循 lego 期望的响应结构。
type fakeCA struct {
	t        *testing.T
	srv      *httptest.Server
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	mu       sync.Mutex
	nonce    int64
	domains  []string
	issued   []byte
	serial   int64
	requests []string
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fnGate Test CA", Organization: []string{"fnGate"}},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &fakeCA{t: t, cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	ca.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ca.mu.Lock()
		ca.nonce++
		n := fmt.Sprintf("nonce-%d", ca.nonce)
		ca.requests = append(ca.requests, r.Method+" "+r.URL.Path)
		ca.mu.Unlock()
		w.Header().Set("Replay-Nonce", n)
		ca.route(w, r)
	}))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) base() string { return ca.srv.URL }

func (ca *fakeCA) route(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path
	switch {
	case p == "/dir":
		writeJSONFake(ca.t, w, 200, map[string]interface{}{
			"newNonce": ca.base() + "/nonce", "newAccount": ca.base() + "/account",
			"newOrder": ca.base() + "/new-order", "revokeCert": ca.base() + "/revoke",
			"keyChange": ca.base() + "/key-change",
			"meta": map[string]interface{}{
				"termsOfService": ca.base() + "/tos", "externalAccountRequired": false,
			},
		})
	case p == "/nonce":
		w.WriteHeader(http.StatusNoContent)
	case p == "/account":
		w.Header().Set("Location", ca.base()+"/acct/1")
		writeJSONFake(ca.t, w, 201, map[string]string{"status": "valid"})
	case p == "/new-order":
		var payload struct {
			Identifiers []map[string]string `json:"identifiers"`
		}
		decodeJWS(ca.t, r, &payload)
		idents := payload.Identifiers
		if len(idents) == 0 {
			idents = []map[string]string{{"type": "dns", "value": "example.com"}}
		}
		ca.mu.Lock()
		ca.domains = make([]string, 0, len(idents))
		authz := make([]string, 0, len(idents))
		for i, id := range idents {
			ca.domains = append(ca.domains, id["value"])
			authz = append(authz, fmt.Sprintf("%s/authz/%d", ca.base(), i))
		}
		ca.mu.Unlock()
		w.Header().Set("Location", ca.base()+"/order/1")
		writeJSONFake(ca.t, w, 201, map[string]interface{}{
			"status": "pending", "identifiers": idents, "authorizations": authz,
			"finalize": ca.base() + "/finalize",
			"expires":  time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	case strings.HasPrefix(p, "/authz/"):
		idx := 0
		_, _ = fmt.Sscanf(strings.TrimPrefix(p, "/authz/"), "%d", &idx)
		ca.mu.Lock()
		domains := append([]string(nil), ca.domains...)
		ca.mu.Unlock()
		domain := "example.com"
		wildcard := false
		if idx < len(domains) {
			domain = strings.TrimPrefix(domains[idx], "*.")
			wildcard = strings.HasPrefix(domains[idx], "*.")
		}
		writeJSONFake(ca.t, w, 200, map[string]interface{}{
			"status": "pending", "identifier": map[string]string{"type": "dns", "value": domain},
			"wildcard": wildcard,
			"challenges": []map[string]string{{
				"type": "dns-01", "url": fmt.Sprintf("%s/chall/%d", ca.base(), idx),
				"status": "pending", "token": fmt.Sprintf("token-%d", idx),
			}},
		})
	case strings.HasPrefix(p, "/chall/"):
		idx := 0
		_, _ = fmt.Sscanf(strings.TrimPrefix(p, "/chall/"), "%d", &idx)
		writeJSONFake(ca.t, w, 200, map[string]string{
			"type": "dns-01", "url": fmt.Sprintf("%s/chall/%d", ca.base(), idx),
			"status": "valid", "token": fmt.Sprintf("token-%d", idx),
		})
	case p == "/finalize":
		var payload struct {
			CSR string `json:"csr"`
		}
		decodeJWS(ca.t, r, &payload)
		der, err := base64.RawURLEncoding.DecodeString(payload.CSR)
		if err != nil {
			ca.t.Errorf("CSR base64 解码失败: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			ca.t.Errorf("CSR 解析失败: %v", err)
		}
		ca.mu.Lock()
		ca.serial++
		serial := ca.serial
		ca.mu.Unlock()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(100 + serial), Subject: csr.Subject,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 90),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              csr.DNSNames, IPAddresses: csr.IPAddresses,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
		if err != nil {
			ca.t.Errorf("签发证书失败: %v", err)
		}
		chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), ca.certPEM...)
		ca.mu.Lock()
		ca.issued = chain
		idents := make([]map[string]string, 0, len(ca.domains))
		for _, d := range ca.domains {
			idents = append(idents, map[string]string{"type": "dns", "value": d})
		}
		ca.mu.Unlock()
		writeJSONFake(ca.t, w, 200, map[string]interface{}{
			"status": "valid", "identifiers": idents,
			"authorizations": []string{ca.base() + "/authz/0"},
			"finalize":       ca.base() + "/finalize",
			"certificate":    ca.base() + "/cert",
		})
	case p == "/cert":
		ca.mu.Lock()
		chain := append([]byte(nil), ca.issued...)
		ca.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = w.Write(chain)
	case p == "/order/1":
		writeJSONFake(ca.t, w, 200, map[string]interface{}{
			"status": "valid", "certificate": ca.base() + "/cert",
		})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"unknown path"}`))
	}
}

func writeJSONFake(t *testing.T, w http.ResponseWriter, code int, v interface{}) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Errorf("序列化失败: %v", err)
		return
	}
	w.WriteHeader(code)
	_, _ = w.Write(raw)
}

func decodeJWS(t *testing.T, r *http.Request, dst interface{}) {
	t.Helper()
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		t.Errorf("JWS 解析失败: %v", err)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		t.Errorf("JWS payload 解码失败: %v", err)
		return
	}
	if len(raw) == 0 {
		return
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Errorf("JWS payload JSON 解析失败: %v (%s)", err, raw)
	}
}

// confirmManualSoon 在任务进入执行态后立刻确认 TXT 已添加，
// 跳过真实 DNS 传播等待，同时仍会走完整的 Present / PreSolve 链路。
func confirmManualSoon(t *testing.T, m *Manager, orderID string, stop <-chan struct{}) {
	t.Helper()
	go func() {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if h := m.getRun(orderID); h != nil && h.manual != nil {
					h.manual.confirmed.Store(true)
					return
				}
			}
		}
	}()
}

func waitOrder(t *testing.T, m *Manager, id string, timeout time.Duration) core.ACMEOrder {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		o, ok := m.order(id)
		if ok && (o.Status == "done" || o.Status == "failed" || o.Status == "canceled") {
			return o
		}
		time.Sleep(10 * time.Millisecond)
	}
	o, _ := m.order(id)
	t.Fatalf("订单 %s 在 %v 内未结束：%+v", id, timeout, o)
	return core.ACMEOrder{}
}

func TestEndToEndACMEIssueAndRenew(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	ca := newFakeCA(t)
	h := newHarness(t, false)
	h.m.manualInterval = 10 * time.Millisecond
	go h.m.worker()
	t.Cleanup(func() { h.m.Close() })

	p := h.addManualProvider(t)
	dir := ca.base() + "/dir"
	acc := core.ACMEAccount{
		ID: "acc-e2e", CA: CACustom, DirectoryURL: dir,
		Email: "admin@example.com", KeyPath: accountKeyPath("acc-e2e"), CreatedAt: nowText(),
	}
	if err := h.store.Update(func(st *core.State) error {
		st.ACMEAccounts = append(st.ACMEAccounts, acc)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	o, err := h.m.CreateOrder(OrderPayload{
		Domains: []string{"example.com", "*.example.com"}, ProviderID: p.ID,
		AccountID: acc.ID, CA: CACustom, DirectoryURL: dir,
		KeyType: "ec256", AutoRenew: boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	confirmManualSoon(t, h.m, o.ID, stop)

	done := waitOrder(t, h.m, o.ID, 20*time.Second)
	if done.Status != "done" {
		t.Fatalf("签发未成功：status=%s error=%s logs=%v", done.Status, done.Error, done.Logs)
	}
	if done.CertID == "" {
		t.Fatal("订单未回填 cert_id")
	}

	c, ok := h.certs.ByID(done.CertID)
	if !ok {
		t.Fatal("证书未入库")
	}
	if c.Source != "acme" || c.ACME == nil || !c.ACME.AutoRenew {
		t.Fatalf("证书元数据不对：%+v", c)
	}
	if c.ACME.KeyType != "ec256" || c.ACME.Challenge != "dns-01" || c.ACME.AccountID != acc.ID {
		t.Fatalf("ACME 元数据不对：%+v", c.ACME)
	}
	hasRoot, hasWild := false, false
	for _, d := range c.SANs {
		if d == "example.com" {
			hasRoot = true
		}
		if d == "*.example.com" {
			hasWild = true
		}
	}
	if !hasRoot || !hasWild {
		t.Fatalf("泛域名 SAN 缺失：%v", c.SANs)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "secrets", "acme", "acc-e2e", "registration.json")); err != nil {
		t.Fatalf("ACME 注册信息未持久化：%v", err)
	}

	// 证书能被 HTTPS 握手解析，且泛域名 SNI 能自动命中。
	got, err := h.certs.Get(c.ID, "example.com")
	if err != nil || got == nil {
		t.Fatalf("证书无法用于 TLS 握手：%v", err)
	}
	fb, err := h.certs.Fallback("sub.example.com")
	if err != nil || fb == nil {
		t.Fatalf("泛域名 SNI 回退失败：%v", err)
	}
	firstSerial := leafSerial(t, fb)

	// 续期：cert_id 不变，文件原子替换，下次握手立即拿到新证书（零重启）。
	renew, err := h.m.RenewNow(c.ID)
	if err != nil {
		t.Fatalf("续期排队失败：%v", err)
	}
	stop2 := make(chan struct{})
	defer close(stop2)
	confirmManualSoon(t, h.m, renew.ID, stop2)
	rdone := waitOrder(t, h.m, renew.ID, 20*time.Second)
	if rdone.Status != "done" {
		t.Fatalf("续期失败：status=%s error=%s logs=%v", rdone.Status, rdone.Error, rdone.Logs)
	}
	if rdone.CertID != c.ID {
		t.Fatal("续期后 cert_id 应保持不变，否则反代引用会失效")
	}
	st := h.store.Snapshot()
	if len(st.Certificates) != 1 {
		t.Fatalf("续期不应产生重复证书：%d", len(st.Certificates))
	}
	after, _ := h.certs.ByID(c.ID)
	if after.Fingerprint == c.Fingerprint {
		t.Fatal("续期后证书指纹未变化，说明新证书没有落盘")
	}
	// 强制推进 mtime，模拟真实落盘时间变化。
	bump := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(h.dir, "certs", c.ID, "fullchain.pem"), bump, bump)
	_ = os.Chtimes(filepath.Join(h.dir, "secrets", "certs", c.ID, "privkey.pem"), bump, bump)
	got2, err := h.certs.Get(c.ID, "example.com")
	if err != nil {
		t.Fatalf("续期后握手失败：%v", err)
	}
	secondSerial := leafSerial(t, got2)
	if firstSerial == nil || secondSerial == nil {
		t.Fatal("证书链无法解析")
	}
	if secondSerial.Cmp(firstSerial) == 0 {
		t.Fatal("续期后握手仍返回旧证书：mtime 失效检测或原子替换未生效")
	}

	// state.json 里绝不能出现私钥内容。
	raw, err := os.ReadFile(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("state.json 泄露了私钥")
	}
	ca.mu.Lock()
	reqs := append([]string(nil), ca.requests...)
	ca.mu.Unlock()
	for _, want := range []string{"POST /new-order", "POST /finalize", "POST /cert"} {
		found := false
		for _, rq := range reqs {
			if rq == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("未走到 ACME 流程的 %s，实际请求：%v", want, reqs)
		}
	}
}

func leafSerial(t *testing.T, c *tls.Certificate) *big.Int {
	t.Helper()
	if c == nil || len(c.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber
}
