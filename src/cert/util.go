package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"fngate/core"
)

// Details 是从证书对里解析出来的元数据，绝不包含私钥内容。
type Details struct {
	PrimaryDomain string
	SANs          []string
	Issuer        string
	NotBefore     string
	NotAfter      string
	Fingerprint   string
	KeyType       string
	Wildcard      bool
	ChainLength   int
}

// Inspect 校验「证书链 + 私钥」是否配套，并解析出可展示的元数据。
// 用 tls.X509KeyPair 而非单独解析 PEM，能同时验证密钥匹配与链顺序。
func Inspect(certPEM, keyPEM []byte) (*Details, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("证书链与私钥都不能为空")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, humanizePairErr(err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("证书链里没有证书")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("证书格式无法解析：%v", err)
	}
	for i, der := range pair.Certificate[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("证书链第 %d 张中间证书格式错误：%v", i+2, err)
		}
	}

	sans := make([]string, 0, len(leaf.DNSNames))
	seen := map[string]bool{}
	for _, d := range leaf.DNSNames {
		d = normalizeDomain(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		sans = append(sans, d)
	}
	if len(sans) == 0 && strings.TrimSpace(leaf.Subject.CommonName) != "" {
		sans = append(sans, normalizeDomain(leaf.Subject.CommonName))
	}
	sort.Strings(sans)

	primary := normalizeDomain(leaf.Subject.CommonName)
	if primary == "" && len(sans) > 0 {
		primary = sans[0]
	}
	// 主域名优先取不带星号的那一项（ACME 泛域名证书会同时含 example.com 与 *.example.com）。
	for _, d := range sans {
		if !strings.HasPrefix(d, "*.") {
			primary = d
			break
		}
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	if issuer == "" {
		issuer = leaf.Issuer.String()
	}

	wildcard := false
	for _, d := range sans {
		if strings.HasPrefix(d, "*.") {
			wildcard = true
			break
		}
	}

	return &Details{
		PrimaryDomain: primary,
		SANs:          sans,
		Issuer:        issuer,
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint:   fmt.Sprintf("%x", sha256.Sum256(leaf.Raw)),
		KeyType:       keyTypeOf(pair.PrivateKey),
		Wildcard:      wildcard,
		ChainLength:   len(pair.Certificate),
	}, nil
}

func humanizePairErr(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "private key does not match"), strings.Contains(s, "mismatch"):
		return fmt.Errorf("私钥与证书不匹配，请检查是否上传了同一套证书文件")
	case strings.Contains(s, "failed to find any PEM data"), strings.Contains(s, "no certificates"):
		return fmt.Errorf("未找到有效的 PEM 证书，请粘贴 -----BEGIN CERTIFICATE----- 开头的完整内容")
	case strings.Contains(s, "failed to parse private key"), strings.Contains(s, "PRIVATE KEY"):
		return fmt.Errorf("私钥格式无法识别，支持 PKCS#1 / PKCS#8 / EC 私钥的 PEM 格式")
	case strings.Contains(s, "certificate contains no PEM data"):
		return fmt.Errorf("证书链内容为空或不是 PEM 格式")
	}
	return fmt.Errorf("证书与私钥校验失败：%v", err)
}

func keyTypeOf(k interface{}) string {
	switch v := k.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA %d", v.N.BitLen())
	case *ecdsa.PrivateKey:
		return "ECDSA " + v.Curve.Params().Name
	case ed25519.PrivateKey:
		return "Ed25519"
	}
	return "未知"
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	if i := strings.IndexByte(s, ':'); i >= 0 && !strings.Contains(s, "]") {
		s = s[:i]
	}
	return s
}

// MatchDomain 支持精确域名、单级泛域名与「留空匹配任意」。
func MatchDomain(pattern, host string) bool {
	pattern = normalizeDomain(pattern)
	host = normalizeDomain(host)
	if pattern == "" {
		return true
	}
	if host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	base := strings.TrimPrefix(pattern, "*.")
	if host == base || !strings.HasSuffix(host, "."+base) {
		return false
	}
	rest := strings.TrimSuffix(host, "."+base)
	return rest != "" && !strings.Contains(rest, ".")
}

// BestCertByHost 按「精确域名 > 泛域名 > 任意证书」挑选最合适的证书。
// 同级别里优先选有效期更晚的一张，避免续期过渡期选到旧证书。
func BestCertByHost(certs []core.Certificate, host string) *core.Certificate {
	var exact, wild *core.Certificate
	for i := range certs {
		c := &certs[i]
		if c.NotAfter == "" || !filesUsable(*c) {
			continue
		}
		if _, status := expiryOf(c.NotAfter); status == "expired" {
			continue
		}
		best := false
		kind := 0
		for _, d := range c.SANs {
			switch {
			case normalizeDomain(d) == normalizeDomain(host) && normalizeDomain(d) != "":
				kind, best = 2, true
			case strings.HasPrefix(normalizeDomain(d), "*.") && kind < 1 && MatchDomain(d, host):
				kind, best = 1, true
			}
		}
		if !best {
			continue
		}
		target := &wild
		if kind == 2 {
			target = &exact
		}
		if *target == nil || c.NotAfter > (*target).NotAfter {
			*target = c
		}
	}
	if exact != nil {
		return exact
	}
	return wild
}

func filesUsable(c core.Certificate) bool {
	return c.CertPath != "" && c.KeyPath != ""
}

func newID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func nowText() string { return time.Now().Format("2006-01-02 15:04:05") }

func expiryOf(notAfter string) (int, string) {
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		// 兼容早期手工写入的本地时间格式。
		t, err = time.ParseInLocation("2006-01-02 15:04:05", notAfter, time.Local)
		if err != nil {
			return 0, "unknown"
		}
	}
	days := int(time.Until(t).Hours() / 24)
	switch {
	case days < 0:
		return days, "expired"
	case days <= 30:
		return days, "expiring"
	default:
		return days, "valid"
	}
}
