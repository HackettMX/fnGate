package deployer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// 证书解析与校验：用 Go 标准库实现参考实现 inspectDeploymentCertificate /
// assertPublicTrust 的等价检查。
//
// 真机上的证书文件未必是本应用生成的干净 PEM：fnOS 的导入路径可能保留
// openssl 输出的 "Bag Attributes" 前缀、UTF-8 BOM，或把私钥一并写进 crt。
// 这些都不影响 nginx 加载（OpenSSL 会跳过 PEM 之前的文本），因此读取时按
// PEM 块解析而不是按整文件严格匹配；但每一层失败都必须带上可读出的事实。

var domainPattern = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// nowFunc / rootCAs 便于测试替换，定义在 engine.go。

func validDomainName(s string) bool {
	return len(s) <= 253 && domainPattern.MatchString(s)
}

// pemScan 是 PEM 文件的轻量结构描述，仅用于诊断（不含任何密钥内容）。
type pemScan struct {
	Types   []string // 每个 PEM 块的类型，按出现顺序
	Ignored int      // PEM 块之外的非空文本字节数（BOM、openssl 属性行等）
	Head    string   // 被忽略文本的首行（截断、去控制字符）
}

func (s *pemScan) addText(t string) {
	if t == "" {
		return
	}
	s.Ignored += len(t)
	if s.Head == "" {
		s.Head = firstLine(t, 60)
	}
}

// hint 生成一段可直接展示的文件结构说明。
func (s *pemScan) hint() string {
	parts := []string{}
	if len(s.Types) > 0 {
		count := map[string]int{}
		order := []string{}
		for _, t := range s.Types {
			if count[t] == 0 {
				order = append(order, t)
			}
			count[t]++
		}
		items := make([]string, 0, len(order))
		for _, t := range order {
			if count[t] > 1 {
				items = append(items, fmt.Sprintf("%s×%d", t, count[t]))
			} else {
				items = append(items, t)
			}
		}
		parts = append(parts, "PEM 块 "+strings.Join(items, "、"))
	} else {
		parts = append(parts, "不含任何 PEM 块")
	}
	if s.Ignored > 0 {
		parts = append(parts, fmt.Sprintf("非 PEM 文本 %d 字节（开头 %q）", s.Ignored, s.Head))
	}
	return "（" + strings.Join(parts, "；") + "）"
}

// scanPEM 解码所有 PEM 块，同时统计块之间被忽略的文本。
func scanPEM(raw []byte) (*pemScan, []*pem.Block) {
	sc := &pemScan{}
	blocks := []*pem.Block{}
	rest := raw
	for i := 0; i < 64; i++ {
		blk, next := pem.Decode(rest)
		if blk == nil {
			sc.addText(strings.TrimSpace(string(rest)))
			break
		}
		if idx := strings.Index(string(rest), "-----BEGIN "); idx > 0 {
			sc.addText(strings.TrimSpace(string(rest[:idx])))
		}
		sc.Types = append(sc.Types, blk.Type)
		blocks = append(blocks, blk)
		rest = next
	}
	return sc, blocks
}

func firstLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}

// firstDERElement 截出 DER 编码里的第一个完整元素（openssl 的
// TRUSTED CERTIFICATE 会在证书之后追加信任数据）。
func firstDERElement(der []byte) ([]byte, bool) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) == 0 {
		return nil, false
	}
	return der[:len(der)-len(rest)], true
}

// inspectCertificate 解析并校验一套 PEM。allowExpired 用于读取系统里已过期的目标证书。
func inspectCertificate(certPEM, keyPEM []byte, allowExpired bool) (*parsedCert, error) {
	const maxCert, maxKey = 512 << 10, 32 << 10
	switch {
	case len(certPEM) == 0:
		return nil, failDetail(CodeInvalid, "cert-size", "证书文件为空")
	case len(certPEM) > maxCert:
		return nil, failDetail(CodeInvalid, "cert-size",
			fmt.Sprintf("证书文件 %d 字节，超过 512 KiB 上限；certificate 字段可能指向了别的文件", len(certPEM)))
	case len(keyPEM) == 0:
		return nil, failDetail(CodeInvalid, "key-size", "私钥文件为空")
	case len(keyPEM) > maxKey:
		return nil, failDetail(CodeInvalid, "key-size",
			fmt.Sprintf("私钥文件 %d 字节，超过 32 KiB 上限", len(keyPEM)))
	}

	certScan, certBlocks := scanPEM(certPEM)
	chain, err := parseCertBlocks(certBlocks)
	if err != nil && len(certBlocks) == 0 {
		// 少数系统把 .crt 存成 DER；没有 PEM 块时按 DER 再试一次。
		if certs, derr := x509.ParseCertificates(certPEM); derr == nil && len(certs) > 0 && len(certs) <= 12 {
			chain, err = certs, nil
		}
	}
	if err != nil {
		return nil, failDetail(CodeInvalid, "cert-blocks", err.Error()+certScan.hint())
	}

	key, keyDesc, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, failDetail(CodeInvalid, "key-blocks", err.Error())
	}

	leaf, why := pickLeaf(chain, key, keyDesc)
	if leaf == nil {
		return nil, failDetail(CodeInvalid, "key-pair", why)
	}

	ordered := orderChain(chain, leaf)

	if !allowExpired {
		now := nowFunc()
		for _, c := range ordered {
			if c.NotBefore.After(now) || !c.NotAfter.After(now) {
				return nil, failDetail(CodeInvalid, "validity",
					fmt.Sprintf("证书不在有效期内：%s 至 %s（CN=%s）",
						c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.Subject.CommonName))
			}
		}
	}

	// SAN 只取合法 DNS 名；IP/email/URI 不影响 nginx 加载，也不再作为拒绝理由。
	names := []string{}
	for _, d := range leaf.DNSNames {
		if validDomainName(strings.ToLower(strings.TrimSuffix(d, "."))) {
			names = append(names, d)
		}
	}
	if len(names) == 0 {
		return nil, failDetail(CodeInvalid, "san",
			fmt.Sprintf("证书没有可用的 DNS 名称：DNSNames %d 个（均非法）、IP %d 个、email %d 个、URI %d 个%s",
				len(leaf.DNSNames), len(leaf.IPAddresses), len(leaf.EmailAddresses), len(leaf.URIs), certScan.hint()))
	}

	encryptType := encryptTypeOf(leaf)
	if encryptType == "" {
		encryptType = strings.ToUpper(leaf.PublicKeyAlgorithm.String())
	}
	issuerCN := leaf.Issuer.CommonName
	if issuerCN == "" {
		issuerCN = leaf.Issuer.String()
	}

	// 按叶子→签发者重排后重新编码，保证 nginx 收到的是「叶子在前」的顺序。
	var chainBuf, issuerBuf strings.Builder
	for i, c := range ordered {
		blk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		chainBuf.Write(blk)
		if i > 0 {
			issuerBuf.Write(blk)
		}
	}

	return &parsedCert{
		Chain:       ordered,
		Leaf:        leaf,
		Domains:     cleanDomains(names),
		Fingerprint: fingerprint256(leaf.Raw),
		ValidFromMS: leaf.NotBefore.UnixMilli(),
		ValidToMS:   leaf.NotAfter.UnixMilli(),
		EncryptType: encryptType,
		IssuedBy:    issuerCN,
		ChainPEM:    []byte(chainBuf.String()),
		IssuerPEM:   []byte(issuerBuf.String()),
	}, nil
}

// parseCertBlocks 抽取所有证书块，返回按文件顺序的证书列表。
func parseCertBlocks(blocks []*pem.Block) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{}
	bad := []string{}
	for _, b := range blocks {
		if b.Type != "CERTIFICATE" && b.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil && b.Type == "TRUSTED CERTIFICATE" {
			if der, ok := firstDERElement(b.Bytes); ok {
				if c2, err2 := x509.ParseCertificate(der); err2 == nil {
					c, err = c2, nil
				}
			}
		}
		if err != nil {
			bad = append(bad, fmt.Sprintf("第 %d 个 %s 块无法解析（%v）", len(chain)+len(bad)+1, b.Type, err))
			continue
		}
		chain = append(chain, c)
		if len(chain) > 12 {
			return nil, errors.New("证书块超过 12 个，可能是把多张证书拼在了一起")
		}
	}
	if len(bad) > 0 {
		return nil, errors.New(strings.Join(bad, "；"))
	}
	if len(chain) == 0 {
		return nil, errors.New("没有 CERTIFICATE 块")
	}
	return chain, nil
}

// parseKeyPEM 按键块逐个尝试常见私钥编码，返回签名器与可读描述。
func parseKeyPEM(keyPEM []byte) (crypto.Signer, string, error) {
	sc, blocks := scanPEM(keyPEM)
	seen := []string{}
	for _, b := range blocks {
		if !strings.Contains(b.Type, "PRIVATE KEY") {
			continue
		}
		seen = append(seen, b.Type)
		if k, ok := parseKeyDER(b.Bytes); ok {
			return k, keyText(k), nil
		}
	}
	if len(seen) == 0 {
		// 没有 PRIVATE KEY 块时按 DER 私钥再试一次。
		if k, ok := parseKeyDER(keyPEM); ok {
			return k, keyText(k), nil
		}
		return nil, "", fmt.Errorf("私钥文件里没有 PRIVATE KEY 块%s", sc.hint())
	}
	return nil, "", fmt.Errorf("私钥无法解析（块类型 %s，可能是带口令的加密私钥或非常规编码）",
		strings.Join(seen, "、"))
}

// parseKeyDER 尝试把裸 DER 解析成私钥。
func parseKeyDER(der []byte) (crypto.Signer, bool) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, true
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, true
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, true
	}
	return nil, false
}

// keyText 给出「算法 位数」形式的中性描述。
func keyText(k crypto.Signer) string {
	switch pub := k.Public().(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d 位", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %d 位", pub.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "未知算法"
	}
}

// pickLeaf 在证书块中找出与私钥配对、且不是 CA 的站点证书。
func pickLeaf(chain []*x509.Certificate, key crypto.Signer, keyDesc string) (*x509.Certificate, string) {
	var caMatch *x509.Certificate
	for _, c := range chain {
		if !publicKeyMatches(c, key) {
			continue
		}
		if c.IsCA {
			caMatch = c
			continue
		}
		return c, ""
	}
	if caMatch != nil {
		return nil, fmt.Sprintf("与私钥匹配的证书是 CA 证书（CN=%s），文件里缺少站点证书",
			caMatch.Subject.CommonName)
	}
	algs := make([]string, 0, len(chain))
	for _, c := range chain {
		algs = append(algs, publicKeyText(c))
	}
	return nil, fmt.Sprintf("私钥与证书公钥不匹配：证书 %s，私钥 %s；"+
		"certificate 与 private_key 很可能指向了不同证书的文件", strings.Join(algs, "、"), keyDesc)
}

// orderChain 按「叶子 → 签发者」重排；未连上的块（通常是根证书或无关证书）不参与。
func orderChain(chain []*x509.Certificate, leaf *x509.Certificate) []*x509.Certificate {
	ordered := []*x509.Certificate{leaf}
	used := map[*x509.Certificate]bool{leaf: true}
	cur := leaf
	for len(ordered) < 12 {
		var next *x509.Certificate
		for _, c := range chain {
			if used[c] {
				continue
			}
			if string(cur.RawIssuer) == string(c.RawSubject) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		ordered = append(ordered, next)
		used[next] = true
		cur = next
	}
	return ordered
}

// publicKeyText 描述证书公钥算法与长度。
func publicKeyText(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d 位", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %d 位", pub.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return strings.ToUpper(c.PublicKeyAlgorithm.String())
	}
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
