package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"fngate/core"
)

// GenerateSelfSigned 生成一张 ECDSA P-256 自签证书，用于内网测试或无域名场景。
// 自签证书不受浏览器信任，界面会明确提示仅适合临时使用。
func GenerateSelfSigned(domains []string) ([]byte, []byte, error) {
	clean := make([]string, 0, len(domains))
	seen := map[string]bool{}
	var ips []net.IP
	for _, raw := range domains {
		d := normalizeDomain(raw)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if ip := net.ParseIP(strings.Trim(d, "[]")); ip != nil {
			ips = append(ips, ip)
			continue
		}
		clean = append(clean, d)
	}
	if len(clean) == 0 && len(ips) == 0 {
		clean = []string{"localhost"}
		ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	cn := clean[0]
	if cn == "" && len(ips) > 0 {
		cn = ips[0].String()
	}
	// 通配符写成 DNSName 时保留 *. 前缀，x509 能正常编码。
	dnsNames := make([]string, 0, len(clean))
	for _, d := range clean {
		dnsNames = append(dnsNames, d)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"fnGate"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func (m *Manager) AddSelfSigned(name string, domains []string) (core.Certificate, error) {
	certPEM, keyPEM, err := GenerateSelfSigned(domains)
	if err != nil {
		return core.Certificate{}, fmt.Errorf("生成自签证书失败：%w", err)
	}
	d, err := Inspect(certPEM, keyPEM)
	if err != nil {
		return core.Certificate{}, err
	}
	if name == "" {
		name = "自签 · " + d.PrimaryDomain
	}
	return m.insert(newID(), name, "selfsigned", d, certPEM, keyPEM, nil)
}
