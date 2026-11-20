package deployer

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
)

// 证书解析与校验：用 Go 标准库实现参考实现 inspectDeploymentCertificate /
// assertPublicTrust 的等价检查。

var domainPattern = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// nowFunc / rootCAs 便于测试替换，定义在 engine.go。

func validDomainName(s string) bool {
	return len(s) <= 253 && domainPattern.MatchString(s)
}

// inspectCertificate 解析并校验一套 PEM。allowExpired 用于读取系统里已过期的目标证书。
func inspectCertificate(certPEM, keyPEM []byte, allowExpired bool) (*parsedCert, error) {
	if len(certPEM) == 0 || len(certPEM) > 512*1024 || len(keyPEM) == 0 || len(keyPEM) > 32*1024 {
		return nil, fail(CodeInvalid)
	}
	if !onlyCertificateBlocks(certPEM) {
		return nil, fail(CodeInvalid)
	}

	var chain []*x509.Certificate
	var derBlocks [][]byte
	rest := certPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fail(CodeInvalid)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fail(CodeInvalid)
		}
		chain = append(chain, c)
		derBlocks = append(derBlocks, blk.Bytes)
		if len(chain) > 12 {
			return nil, fail(CodeInvalid)
		}
	}
	if len(chain) == 0 {
		return nil, fail(CodeInvalid)
	}

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fail(CodeInvalid)
	}

	leaf := chain[0]
	if leaf.IsCA || !publicKeyMatches(leaf, key) {
		return nil, fail(CodeInvalid)
	}

	now := nowFunc()
	for i, c := range chain {
		if !allowExpired && (c.NotBefore.After(now) || !c.NotAfter.After(now)) {
			return nil, fail(CodeInvalid)
		}
		if i > 0 {
			if !chain[i-1].IsCA || chain[i-1].CheckSignatureFrom(c) != nil {
				return nil, fail(CodeInvalid)
			}
		}
	}

	// SAN 只允许合法 DNS 名，不接受 IP / email / URI，与参考实现一致。
	if len(leaf.DNSNames) == 0 || len(leaf.IPAddresses) > 0 ||
		len(leaf.EmailAddresses) > 0 || len(leaf.URIs) > 0 {
		return nil, fail(CodeInvalid)
	}
	for _, d := range leaf.DNSNames {
		if !validDomainName(strings.ToLower(d)) {
			return nil, fail(CodeInvalid)
		}
	}

	encryptType := encryptTypeOf(leaf)
	if encryptType == "" {
		return nil, fail(CodeInvalid)
	}
	issuerCN := leaf.Issuer.CommonName
	if issuerCN == "" {
		issuerCN = leaf.Issuer.String()
	}

	var chainBuf, issuerBuf strings.Builder
	for _, der := range derBlocks {
		chainBuf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	for _, der := range derBlocks[1:] {
		issuerBuf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	return &parsedCert{
		Chain:       chain,
		Leaf:        leaf,
		Domains:     cleanDomains(leaf.DNSNames),
		Fingerprint: fingerprint256(derBlocks[0]),
		ValidFromMS: leaf.NotBefore.UnixMilli(),
		ValidToMS:   leaf.NotAfter.UnixMilli(),
		EncryptType: encryptType,
		IssuedBy:    issuerCN,
		ChainPEM:    []byte(chainBuf.String()),
		IssuerPEM:   []byte(issuerBuf.String()),
	}, nil
}

func encryptTypeOf(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	default:
		return ""
	}
}

// onlyCertificateBlocks 确认 PEM 之外没有非空白内容，块数 1..12。
func onlyCertificateBlocks(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	count := 0
	for len(s) > 0 {
		if !strings.HasPrefix(s, "-----BEGIN CERTIFICATE-----") {
			return false
		}
		end := strings.Index(s, "-----END CERTIFICATE-----")
		if end < 0 {
			return false
		}
		end += len("-----END CERTIFICATE-----")
		count++
		s = strings.TrimSpace(s[end:])
		if count > 12 {
			return false
		}
	}
	return count > 0
}

func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("no pem block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key")
}

func publicKeyMatches(c *x509.Certificate, key crypto.Signer) bool {
	pubDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return false
	}
	derived, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return false
	}
	return string(pubDER) == string(derived)
}

// assertPublicTrust 校验链能被系统根 CA 信任。
func assertPublicTrust(p *parsedCert) error {
	roots, err := rootCAs()
	if err != nil || roots == nil {
		return fail(CodeUntrusted)
	}
	inter := x509.NewCertPool()
	for _, c := range p.Chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   nowFunc(),
	}
	if _, err := p.Leaf.Verify(opts); err != nil {
		return fail(CodeUntrusted)
	}
	return nil
}

// domainCovered 校验探测主机被证书覆盖（叶子 checkHost，忽略 subject CN）。
func domainCovered(p *parsedCert, host string) bool {
	for _, d := range p.Leaf.DNSNames {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if strings.HasPrefix(d, "*.") {
			suffix := d[1:] // ".example.com"
			if strings.HasSuffix(strings.ToLower(host), suffix) &&
				strings.Count(strings.TrimSuffix(strings.ToLower(host), suffix), ".") == 0 {
				return true
			}
			continue
		}
		if d == strings.ToLower(host) {
			return true
		}
	}
	return false
}
