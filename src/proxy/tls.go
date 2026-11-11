package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fngate/core"
)

// CertResolver 由证书模块（M4）实现；M3 阶段使用内置自签兜底。
// 每次 TLS 握手都会调用，因此续期后的证书无需重建监听即可生效。
type CertResolver interface {
	Get(certID, serverName string) (*tls.Certificate, error)
	Fallback(serverName string) (*tls.Certificate, error)
}

type selfSignedResolver struct {
	mu   sync.Mutex
	dir  string
	cert *tls.Certificate
}

func NewSelfSignedResolver(dir string) CertResolver {
	return &selfSignedResolver{dir: dir}
}

func (r *selfSignedResolver) Get(_, serverName string) (*tls.Certificate, error) {
	return r.Fallback(serverName)
}

func (r *selfSignedResolver) Fallback(_ string) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil {
		return r.cert, nil
	}
	certPath := filepath.Join(r.dir, "selfsigned.crt")
	keyPath := filepath.Join(r.dir, "selfsigned.key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		r.cert = &c
		return &c, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fnGate self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "*.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("写入自签证书失败: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("写入自签私钥失败: %w", err)
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	r.cert = &c
	return &c, nil
}

func (m *Manager) tlsConfig(l core.Listener) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if strings.TrimSpace(l.TLS.MinVersion) == "1.3" {
		cfg.MinVersion = tls.VersionTLS13
	}
	if len(l.TLS.ALPN) > 0 {
		cfg.NextProtos = append([]string(nil), l.TLS.ALPN...)
	} else {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	listenerID := l.ID
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sni := NormalizeDomain(hello.ServerName)
		certID := l.TLS.CertID
		if view, ok := m.view.Load().(*runtimeView); ok {
			if r, found := pickRoute(view.routes[listenerID], sni, "/"); found && r.CertID != "" {
				certID = r.CertID
			}
		}
		resolver := m.certResolver()
		if resolver == nil {
			return nil, fmt.Errorf("证书解析器未就绪")
		}
		if certID != "" {
			if c, err := resolver.Get(certID, sni); err == nil && c != nil {
				return c, nil
			} else if err != nil {
				m.log.Warn("证书 %s 加载失败: %v", certID, err)
			}
		}
		return resolver.Fallback(sni)
	}
	return cfg
}
