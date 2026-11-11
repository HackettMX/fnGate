package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"fngate/core"
)

const (
	CALetsEncrypt = "letsencrypt"
	CAStaging     = "letsencrypt-staging"
	CAZeroSSL     = "zerossl"
	CACustom      = "custom"

	LEProductionURL = lego.LEDirectoryProduction
	LEStagingURL    = lego.LEDirectoryStaging
	ZeroSSLURL      = "https://acme.zerossl.com/v2/DV90"
)

// CAPresets 供界面下拉；自定义 CA 由用户填 Directory URL。
func CAPresets() []map[string]string {
	return []map[string]string{
		{"id": CALetsEncrypt, "name": "Let's Encrypt（生产）", "directory_url": LEProductionURL, "eab": "false"},
		{"id": CAStaging, "name": "Let's Encrypt（Staging 测试）", "directory_url": LEStagingURL, "eab": "false"},
		{"id": CAZeroSSL, "name": "ZeroSSL（通常需要 EAB）", "directory_url": ZeroSSLURL, "eab": "true"},
		{"id": CACustom, "name": "自定义 ACME Directory", "directory_url": "", "eab": "optional"},
	}
}

func DirectoryURL(ca, custom string) (string, error) {
	switch ca {
	case CALetsEncrypt, "":
		return LEProductionURL, nil
	case CAStaging:
		return LEStagingURL, nil
	case CAZeroSSL:
		return ZeroSSLURL, nil
	case CACustom:
		u, err := url.Parse(strings.TrimSpace(custom))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return "", fmt.Errorf("自定义 ACME Directory 必须是完整的 http(s) URL")
		}
		return u.String(), nil
	}
	return "", fmt.Errorf("不支持的 CA：%s", ca)
}

// user 实现 lego 的 registration.User，账户密钥与注册信息都放在 secrets/ 下。
type user struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *registration.Resource { return u.reg }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

func accountKeyPath(id string) string    { return fmt.Sprintf("acme/%s/account.key", id) }
func accountRegPath(id string) string    { return fmt.Sprintf("acme/%s/registration.json", id) }
func dnsCredentialPath(id string) string { return fmt.Sprintf("dns/%s.json", id) }

func generateAccountKey() ([]byte, crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return pemBytes, key, nil
}

func parseAccountKey(raw []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("ACME 账户密钥不是合法 PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("不支持的账户密钥类型：%s", block.Type)
}

// loadUser 读取（不存在则创建）账户密钥与注册信息。
func (m *Manager) loadUser(acc core.ACMEAccount) (*user, error) {
	if acc.KeyPath == "" {
		acc.KeyPath = accountKeyPath(acc.ID)
	}
	u := &user{email: acc.Email}
	raw, err := m.store.SecretRead(acc.KeyPath)
	if err != nil {
		pemBytes, key, genErr := generateAccountKey()
		if genErr != nil {
			return nil, genErr
		}
		if err := m.store.SecretWrite(acc.KeyPath, pemBytes); err != nil {
			return nil, fmt.Errorf("保存 ACME 账户密钥失败：%w", err)
		}
		u.key = key
	} else {
		u.key, err = parseAccountKey(raw)
		if err != nil {
			return nil, err
		}
	}
	if regRaw, err := m.store.SecretRead(accountRegPath(acc.ID)); err == nil && len(regRaw) > 0 {
		var res registration.Resource
		if err := json.Unmarshal(regRaw, &res); err == nil && res.URI != "" {
			u.reg = &res
		}
	}
	return u, nil
}

func (m *Manager) saveRegistration(acc core.ACMEAccount, res *registration.Resource) error {
	if res == nil || res.URI == "" {
		return nil
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return m.store.SecretWrite(accountRegPath(acc.ID), raw)
}

// registerIfNeeded 首次使用时向 CA 注册账户；自定义 CA 可用 EAB。
func (m *Manager) registerIfNeeded(client *lego.Client, u *user, acc core.ACMEAccount) error {
	if u.reg != nil && u.reg.URI != "" {
		return nil
	}
	var res *registration.Resource
	var err error
	if acc.EABKID != "" && acc.EABHMAC != "" {
		res, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: acc.EABKID, HmacEncoded: acc.EABHMAC,
		})
	} else {
		if client.GetExternalAccountRequired() {
			return fmt.Errorf("该 CA 要求外部账户绑定（EAB），请在账户设置里填写 KID 与 HMAC")
		}
		res, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return fmt.Errorf("ACME 账户注册失败：%v", err)
	}
	u.reg = res
	if err := m.saveRegistration(acc, res); err != nil {
		return fmt.Errorf("保存 ACME 注册信息失败：%w", err)
	}
	return nil
}
