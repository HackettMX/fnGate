package deployer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, domains []string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestInspectSelfSigned(t *testing.T) {
	cp, kp := selfSigned(t, []string{"nas.example.com", "*.example.com"})
	p, err := inspectCertificate(cp, kp, false)
	if err != nil {
		t.Fatalf("合法自签应通过解析：%v", err)
	}
	if len(p.Domains) != 2 || p.Domains[0] != "*.example.com" {
		t.Fatalf("域名解析/排序不对：%v", p.Domains)
	}
	if p.EncryptType != "ECDSA" {
		t.Fatalf("密钥类型不对：%s", p.EncryptType)
	}
	if len(p.Fingerprint) < 40 {
		t.Fatalf("指纹异常：%s", p.Fingerprint)
	}
}

func TestInspectRejectsMismatchedKey(t *testing.T) {
	cp, _ := selfSigned(t, []string{"a.example.com"})
	_, other := selfSigned(t, []string{"b.example.com"})
	if _, err := inspectCertificate(cp, other, false); err == nil {
		t.Fatal("不匹配的私钥必须被拒绝")
	}
}

func TestDomainCovered(t *testing.T) {
	cp, kp := selfSigned(t, []string{"*.example.com"})
	p, err := inspectCertificate(cp, kp, false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"a.example.com", true},
		{"a.b.example.com", false},
		{"example.com", false},
		{"other.com", false},
	}
	for _, c := range cases {
		if got := domainCovered(p, c.host); got != c.want {
			t.Errorf("domainCovered(%q)=%v, want %v", c.host, got, c.want)
		}
	}
}

func TestVerifyNginxUser(t *testing.T) {
	cases := []struct {
		conf string
		want bool
	}{
		{"user www-data;\nworker_processes auto;", true},
		{"user www-data www-data;", true},
		{"user root;", false},
		{"user www-data nogroup;", false},
		{"user www-data;\nuser root;", false},
		{"# user www-data;", false},
	}
	for _, c := range cases {
		if got := verifyNginxUser(c.conf); got != c.want {
			t.Errorf("verifyNginxUser(%q)=%v, want %v", c.conf, got, c.want)
		}
	}
}

func TestEqualJSONIgnoresKeyOrder(t *testing.T) {
	a := map[string]interface{}{"x": 1.0, "y": "b"}
	b := map[string]interface{}{"y": "b", "x": 1.0}
	if !equalJSON(a, b) {
		t.Fatal("map key 顺序不应影响相等判断")
	}
}

func TestSameFingerprintNormalizes(t *testing.T) {
	a := "AA:BB:CC:dd"
	b := "aabbccdd"
	if !sameFingerprint(a, b) {
		t.Fatal("指纹比较应忽略大小写与冒号")
	}
	if sameFingerprint("", "") {
		t.Fatal("空指纹不应判等")
	}
}

func TestValidDomainName(t *testing.T) {
	cases := map[string]bool{
		"nas.example.com": true,
		"*.example.com":   true,
		"-bad.example.com": false,
		"example":         false, // 参考实现的 domainPattern 要求至少一个点
		"a_b.example.com": false,
	}
	for in, want := range cases {
		if got := validDomainName(in); got != want {
			t.Errorf("validDomainName(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestRowTextLooseTypes(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{json.Number("42"), "42"},
		{float64(7), "7"},
		{int64(9), "9"},
		{"upload", "upload"},
		{[]interface{}{"a.com", "*.a.com"}, "a.com,*.a.com"},
		{map[string]interface{}{"x": 1}, ""}, // 嵌套对象不展开，避免误当路径
		{nil, ""},
	}
	for _, c := range cases {
		if got := rowText(c.in); got != c.want {
			t.Errorf("rowText(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRowStringPicksNumericID(t *testing.T) {
	row := certRow{"id": json.Number("13"), "source": "upload"}
	if got := rowString(row, "id"); got != "13" {
		t.Fatalf("数字 id 应被读出，实际 %q", got)
	}
}

func TestSplitDomainsJSONArray(t *testing.T) {
	got := cleanDomains(splitDomains(`["*.a.com","a.com"]`))
	if !equalJSON(got, []string{"*.a.com", "a.com"}) {
		t.Fatalf("JSON 数组 san 解析不对：%v", got)
	}
	got2 := cleanDomains(splitDomains("a.com, *.a.com"))
	if !equalJSON(got2, []string{"*.a.com", "a.com"}) {
		t.Fatalf("逗号 san 解析不对：%v", got2)
	}
}

func TestNumEqualLooseTypes(t *testing.T) {
	const ms int64 = 1760000000000
	for _, v := range []interface{}{json.Number("1760000000000"), float64(ms), "1760000000000", int64(ms)} {
		if !numEqual(v, ms) {
			t.Errorf("numEqual(%v) 应为 true", v)
		}
	}
	if numEqual("not-a-number", ms) || numEqual(nil, ms) {
		t.Fatal("非法值不应判等")
	}
	// 秒级时间戳不能与毫秒静默相等：单位差异必须靠诊断暴露，不能猜。
	if numEqual(json.Number("1760000000"), ms) {
		t.Fatal("秒/毫秒不应被静默视为相等")
	}
}

func TestFailDetailCarriesDiagnosis(t *testing.T) {
	err := failDetail(CodeProtected, "source", `source="custom"`)
	if detailOf(err) == "" {
		t.Fatal("诊断文本丢失")
	}
	if got := err.Error(); !strings.Contains(got, "custom") {
		t.Fatalf("错误信息未带诊断：%s", got)
	}
}
