package cert

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fngate/core"
)

// Options 是证书模块的运行依赖。系统证书路径只允许来自启动配置，
// 绝不接受 API 参数，避免降权进程借 root helper 读取任意文件。
type Options struct {
	DataDir         string
	CertsDir        string
	SecretsDir      string
	SysConfPaths    []string
	SysSSLRoots     []string
	SysAllowedRoots []string
	Store           *core.Store
	Bus             *core.EventBus
	Logger          *core.Logger
}

type cachedCert struct {
	cert  *tls.Certificate
	stamp string
}

// Manager 同时承担三件事：证书库 CRUD、TLS 握手期的 CertResolver、
// 以及飞牛系统证书快照的导入。它实现 proxy.CertResolver（Go 接口为结构化匹配，
// 因此本包无需 import proxy，不存在循环依赖）。
type Manager struct {
	opt Options

	mu       sync.Mutex
	cache    map[string]cachedCert
	fallback *tls.Certificate
}

func New(opt Options) *Manager {
	if opt.Bus == nil {
		opt.Bus = core.NewEventBus()
	}
	return &Manager{opt: opt, cache: map[string]cachedCert{}}
}

// ---------- 文件读写 ----------

func (m *Manager) CertsDir() string   { return m.opt.CertsDir }
func (m *Manager) SecretsDir() string { return m.opt.SecretsDir }
func (m *Manager) DataDir() string    { return m.opt.DataDir }

func (m *Manager) certFile(id string) string {
	return filepath.Join(m.opt.CertsDir, id, "fullchain.pem")
}
func (m *Manager) keyFile(id string) string {
	return filepath.Join(m.opt.SecretsDir, "certs", id, "privkey.pem")
}

func (m *Manager) relToData(abs string) (string, error) {
	rel, err := filepath.Rel(m.opt.DataDir, abs)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("证书路径超出数据目录")
	}
	return rel, nil
}

func (m *Manager) absFromRel(rel string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(rel)))
	if clean == "" || clean == "." || strings.HasPrefix(clean, "/") ||
		strings.Contains(clean, "..") || strings.Contains(clean, ":") {
		return "", fmt.Errorf("非法的证书路径：%s", rel)
	}
	return filepath.Join(m.opt.DataDir, filepath.FromSlash(clean)), nil
}

// atomicWrite 先写同目录临时文件再 rename，保证握手期不会读到半截 PEM。
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cert-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// WritePair 把证书链与私钥写入私有目录，返回相对 DataDir 的路径。
// 续期时 certID 保持不变、整对文件原子替换，引用方零重启生效。
func (m *Manager) WritePair(id string, certPEM, keyPEM []byte) (string, string, error) {
	if strings.TrimSpace(id) == "" || strings.ContainsAny(id, `/\..`) {
		return "", "", fmt.Errorf("非法的证书 ID")
	}
	if _, err := Inspect(certPEM, keyPEM); err != nil {
		return "", "", err
	}
	cp, kp := m.certFile(id), m.keyFile(id)
	if err := atomicWrite(cp, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("写入证书链失败：%w", err)
	}
	if err := atomicWrite(kp, keyPEM, 0o600); err != nil {
		_ = os.Remove(cp)
		return "", "", fmt.Errorf("写入私钥失败：%w", err)
	}
	// 证书目录要能被 Web 进程遍历；私钥目录保持 0700。
	_ = os.Chmod(filepath.Dir(cp), 0o755)
	_ = os.Chmod(filepath.Dir(kp), 0o700)
	relCert, err := m.relToData(cp)
	if err != nil {
		return "", "", err
	}
	relKey, err := m.relToData(kp)
	if err != nil {
		return "", "", err
	}
	m.Invalidate(id)
	return relCert, relKey, nil
}

func (m *Manager) removeFiles(c core.Certificate) {
	for _, rel := range []string{c.CertPath, c.KeyPath} {
		if rel == "" {
			continue
		}
		p, err := m.absFromRel(rel)
		if err == nil {
			_ = os.Remove(p)
		}
	}
	// 清掉空目录，避免卸载后残留大量空文件夹。
	_ = os.Remove(filepath.Dir(m.certFile(c.ID)))
	_ = os.Remove(filepath.Dir(m.keyFile(c.ID)))
}

func (m *Manager) ReadChain(c core.Certificate) ([]byte, error) {
	p, err := m.absFromRel(c.CertPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// ---------- CertResolver ----------

func fileStamp(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d/%d/%d", fi.ModTime().UnixNano(), fi.Size(), fi.Mode())
}

// load 每次握手都比对文件 mtime / 大小；续期落盘后下一次握手自动换新证书，
// 不需要重建监听、也不会断开已建立的连接。
func (m *Manager) load(c core.Certificate) (*tls.Certificate, error) {
	cp, err := m.absFromRel(c.CertPath)
	if err != nil {
		return nil, err
	}
	kp, err := m.absFromRel(c.KeyPath)
	if err != nil {
		return nil, err
	}
	stamp := fileStamp(cp) + "|" + fileStamp(kp)
	m.mu.Lock()
	if hit, ok := m.cache[c.ID]; ok && hit.stamp == stamp {
		cc := hit.cert
		m.mu.Unlock()
		return cc, nil
	}
	m.mu.Unlock()

	certPEM, err := os.ReadFile(cp)
	if err != nil {
		return nil, fmt.Errorf("证书文件缺失：%s", c.CertPath)
	}
	keyPEM, err := os.ReadFile(kp)
	if err != nil {
		return nil, fmt.Errorf("私钥文件缺失：%s", c.KeyPath)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("证书 %s 文件已损坏：%v", c.ID, err)
	}
	m.mu.Lock()
	m.cache[c.ID] = cachedCert{cert: &pair, stamp: stamp}
	m.mu.Unlock()
	return &pair, nil
}

func (m *Manager) Invalidate(id string) {
	m.mu.Lock()
	delete(m.cache, id)
	m.mu.Unlock()
}

// Get 由 HTTPS 入口的 GetCertificate 回调调用：入口默认证书或路由覆盖证书。
func (m *Manager) Get(certID, serverName string) (*tls.Certificate, error) {
	if certID == "" {
		return m.Fallback(serverName)
	}
	for _, c := range m.opt.Store.Snapshot().Certificates {
		if c.ID == certID {
			return m.load(c)
		}
	}
	return nil, fmt.Errorf("证书 %s 已被删除，请在反向代理中重新选择", certID)
}

// Fallback 的解析顺序：默认证书 → SNI 最佳匹配证书 → 自签兜底。
func (m *Manager) Fallback(serverName string) (*tls.Certificate, error) {
	st := m.opt.Store.Snapshot()
	if id := st.Settings.DefaultCertID; id != "" {
		for _, c := range st.Certificates {
			if c.ID == id {
				if pair, err := m.load(c); err == nil {
					return pair, nil
				}
			}
		}
	}
	if serverName != "" {
		if best := BestCertByHost(st.Certificates, serverName); best != nil {
			if pair, err := m.load(*best); err == nil {
				return pair, nil
			}
		}
	}
	return m.fallbackCert()
}

func (m *Manager) fallbackCert() (*tls.Certificate, error) {
	m.mu.Lock()
	if m.fallback != nil {
		c := m.fallback
		m.mu.Unlock()
		return c, nil
	}
	m.mu.Unlock()

	cp := filepath.Join(m.opt.CertsDir, "default-selfsigned.crt")
	kp := filepath.Join(m.opt.SecretsDir, "default-selfsigned.key")
	if pair, err := tls.LoadX509KeyPair(cp, kp); err == nil {
		m.mu.Lock()
		m.fallback = &pair
		m.mu.Unlock()
		return &pair, nil
	}
	certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost", "fngate.local"})
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(cp, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := atomicWrite(kp, keyPEM, 0o600); err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.fallback = &pair
	m.mu.Unlock()
	return &pair, nil
}

// ---------- 证书库 CRUD ----------

type View struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Source        string         `json:"source"`
	PrimaryDomain string         `json:"primary_domain"`
	SANs          []string       `json:"sans"`
	Issuer        string         `json:"issuer"`
	NotBefore     string         `json:"not_before"`
	NotAfter      string         `json:"not_after"`
	Fingerprint   string         `json:"fingerprint"`
	KeyType       string         `json:"key_type"`
	ChainLength   int            `json:"chain_length"`
	Wildcard      bool           `json:"wildcard"`
	DaysLeft      int            `json:"days_left"`
	Status        string         `json:"status"`
	FilesOK       bool           `json:"files_ok"`
	References    int            `json:"references"`
	AutoRenew     bool           `json:"auto_renew"`
	LastError     string         `json:"last_error,omitempty"`
	NextRenewAt   string         `json:"next_renew_at,omitempty"`
	IsDefault     bool           `json:"is_default"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at"`
	ACME          *core.ACMEMeta `json:"acme,omitempty"`
}

func (m *Manager) viewOf(c core.Certificate, st core.State) View {
	days, status := expiryOf(c.NotAfter)
	_, keyErr := m.absFromRel(c.KeyPath)
	chain, certErr := m.ReadChain(c)
	filesOK := keyErr == nil && certErr == nil && len(chain) > 0
	if !filesOK {
		status = "missing"
	}
	v := View{
		ID: c.ID, Name: c.Name, Source: c.Source, PrimaryDomain: c.PrimaryDomain,
		SANs: c.SANs, Issuer: c.Issuer, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Fingerprint: c.Fingerprint, DaysLeft: days, Status: status, FilesOK: filesOK,
		References: len(m.References(c.ID)), IsDefault: st.Settings.DefaultCertID == c.ID,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, ACME: c.ACME,
	}
	if c.ACME != nil {
		v.AutoRenew = c.ACME.AutoRenew
		v.LastError = c.ACME.LastError
		v.NextRenewAt = c.ACME.NextRenewAt
	}
	// KeyType / ChainLength / Wildcard 从文件实时解析，避免旧配置缺字段。
	if filesOK {
		cp, _ := m.absFromRel(c.CertPath)
		kp, _ := m.absFromRel(c.KeyPath)
		certPEM, e1 := os.ReadFile(cp)
		keyPEM, e2 := os.ReadFile(kp)
		if e1 == nil && e2 == nil {
			if d, err := Inspect(certPEM, keyPEM); err == nil {
				v.KeyType = d.KeyType
				v.ChainLength = d.ChainLength
				v.Wildcard = d.Wildcard
			}
		}
	}
	return v
}

func (m *Manager) List() []View {
	st := m.opt.Store.Snapshot()
	out := make([]View, 0, len(st.Certificates))
	for _, c := range st.Certificates {
		out = append(out, m.viewOf(c, st))
	}
	return out
}

// References 列出引用该证书的入口与路由，删除前用于阻断并提示。
func (m *Manager) References(id string) []string {
	st := m.opt.Store.Snapshot()
	out := []string{}
	for _, l := range st.Listeners {
		if l.TLS.CertID == id {
			out = append(out, fmt.Sprintf("入口「%s」（端口 %d，默认证书）", l.Name, l.Port))
		}
	}
	for _, r := range st.Routes {
		if r.CertID == id {
			out = append(out, fmt.Sprintf("路由「%s」（覆盖证书）", r.Name))
		}
	}
	return out
}

func (m *Manager) ByID(id string) (core.Certificate, bool) {
	for _, c := range m.opt.Store.Snapshot().Certificates {
		if c.ID == id {
			return c, true
		}
	}
	return core.Certificate{}, false
}

func (m *Manager) existsFingerprint(fp string, exceptID string) bool {
	for _, c := range m.opt.Store.Snapshot().Certificates {
		if c.ID != exceptID && c.Fingerprint == fp && fp != "" {
			return true
		}
	}
	return false
}

// AddManual 校验并保存一套手动上传的证书。
func (m *Manager) AddManual(name string, certPEM, keyPEM []byte) (core.Certificate, error) {
	d, err := Inspect(certPEM, keyPEM)
	if err != nil {
		return core.Certificate{}, err
	}
	if m.existsFingerprint(d.Fingerprint, "") {
		return core.Certificate{}, fmt.Errorf("证书库中已存在同一张证书（指纹 %s…）", d.Fingerprint[:12])
	}
	return m.insert(newID(), name, "manual", d, certPEM, keyPEM, nil)
}

// AddACME 供 M5 的 ACME 订单在签发成功后把证书对加入证书库。
func (m *Manager) AddACME(name string, certPEM, keyPEM []byte, meta *core.ACMEMeta) (core.Certificate, error) {
	d, err := Inspect(certPEM, keyPEM)
	if err != nil {
		return core.Certificate{}, err
	}
	if name == "" {
		name = d.PrimaryDomain
	}
	return m.insert(newID(), name, "acme", d, certPEM, keyPEM, meta)
}

// MutateCertificate 让其它模块在保持原子写的前提下修改证书元数据（如续期状态）。
func (m *Manager) MutateCertificate(id string, fn func(*core.Certificate) error) error {
	return m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID == id {
				return fn(&st.Certificates[i])
			}
		}
		return fmt.Errorf("证书 %s 不存在", id)
	})
}

func (m *Manager) insert(id, name, source string, d *Details, certPEM, keyPEM []byte, acme *core.ACMEMeta) (core.Certificate, error) {
	relCert, relKey, err := m.WritePair(id, certPEM, keyPEM)
	if err != nil {
		return core.Certificate{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = d.PrimaryDomain
	}
	c := core.Certificate{
		ID: id, Name: name, Source: source,
		PrimaryDomain: d.PrimaryDomain, SANs: d.SANs, Issuer: d.Issuer,
		NotBefore: d.NotBefore, NotAfter: d.NotAfter, Fingerprint: d.Fingerprint,
		CertPath: relCert, KeyPath: relKey, ACME: acme,
		CreatedAt: nowText(), UpdatedAt: nowText(),
	}
	if err := m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID == id {
				c.CreatedAt = st.Certificates[i].CreatedAt
				st.Certificates[i] = c
				return nil
			}
		}
		st.Certificates = append(st.Certificates, c)
		return nil
	}); err != nil {
		m.removeFiles(c)
		return core.Certificate{}, err
	}
	m.Invalidate(id)
	return c, nil
}

// ReplacePair 用于 ACME 续期：certID 不变，只换文件与元数据。
func (m *Manager) ReplacePair(id string, certPEM, keyPEM []byte, bumpMeta bool) (core.Certificate, error) {
	d, err := Inspect(certPEM, keyPEM)
	if err != nil {
		return core.Certificate{}, err
	}
	existing, ok := m.ByID(id)
	if !ok {
		return core.Certificate{}, fmt.Errorf("证书 %s 不存在", id)
	}
	// 先留一份旧证书对，续期落盘失败时原样回滚，旧证书继续服务。
	oldCertPEM, e1 := m.ReadChain(existing)
	oldKeyPath, e2 := m.absFromRel(existing.KeyPath)
	var oldKeyPEM []byte
	if e2 == nil {
		oldKeyPEM, _ = os.ReadFile(oldKeyPath)
	}
	relCert, relKey, err := m.WritePair(id, certPEM, keyPEM)
	if err != nil {
		return core.Certificate{}, err
	}
	var out core.Certificate
	err = m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID != id {
				continue
			}
			st.Certificates[i].PrimaryDomain = d.PrimaryDomain
			st.Certificates[i].SANs = d.SANs
			st.Certificates[i].Issuer = d.Issuer
			st.Certificates[i].NotBefore = d.NotBefore
			st.Certificates[i].NotAfter = d.NotAfter
			st.Certificates[i].Fingerprint = d.Fingerprint
			st.Certificates[i].CertPath = relCert
			st.Certificates[i].KeyPath = relKey
			st.Certificates[i].UpdatedAt = nowText()
			if bumpMeta && st.Certificates[i].ACME != nil {
				st.Certificates[i].ACME.LastRenewAt = nowText()
				st.Certificates[i].ACME.LastError = ""
				st.Certificates[i].ACME.FailCount = 0
				st.Certificates[i].ACME.NextRenewAt = ""
			}
			out = st.Certificates[i]
			return nil
		}
		return fmt.Errorf("证书 %s 不存在", id)
	})
	if err != nil {
		// 回滚到旧文件，保证续期失败时旧证书继续服务。
		if e1 == nil && len(oldCertPEM) > 0 && len(oldKeyPEM) > 0 {
			_, _, _ = m.WritePair(id, oldCertPEM, oldKeyPEM)
		}
		return core.Certificate{}, err
	}
	m.Invalidate(id)
	return out, nil
}

func (m *Manager) Delete(id string) error {
	refs := m.References(id)
	if len(refs) > 0 {
		return fmt.Errorf("该证书仍被 %d 处引用，请先解除：%s", len(refs), strings.Join(refs[:minInt(3, len(refs))], "；"))
	}
	c, ok := m.ByID(id)
	if !ok {
		return fmt.Errorf("证书不存在")
	}
	if err := m.opt.Store.Update(func(st *core.State) error {
		kept := make([]core.Certificate, 0, len(st.Certificates))
		found := false
		for _, x := range st.Certificates {
			if x.ID == id {
				found = true
				continue
			}
			kept = append(kept, x)
		}
		if !found {
			return fmt.Errorf("证书不存在")
		}
		st.Certificates = kept
		if st.Settings.DefaultCertID == id {
			st.Settings.DefaultCertID = ""
		}
		st.ACMEOrders = removeOrdersFor(st.ACMEOrders, id)
		return nil
	}); err != nil {
		return err
	}
	m.removeFiles(c)
	m.Invalidate(id)
	m.opt.Bus.Publish("cert", "info", "证书「%s」已删除", c.Name)
	return nil
}

func (m *Manager) Rename(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("证书名称不能为空")
	}
	return m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID == id {
				st.Certificates[i].Name = name
				st.Certificates[i].UpdatedAt = nowText()
				return nil
			}
		}
		return fmt.Errorf("证书不存在")
	})
}

func (m *Manager) SetDefault(id string) error {
	if id != "" {
		if _, ok := m.ByID(id); !ok {
			return fmt.Errorf("证书不存在")
		}
	}
	return m.opt.Store.Update(func(st *core.State) error {
		st.Settings.DefaultCertID = id
		return nil
	})
}

func (m *Manager) SetAutoRenew(id string, on bool) error {
	return m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID == id {
				if st.Certificates[i].ACME == nil {
					return fmt.Errorf("只有 ACME 证书支持自动续期")
				}
				st.Certificates[i].ACME.AutoRenew = on
				return nil
			}
		}
		return fmt.Errorf("证书不存在")
	})
}

func removeOrdersFor(orders []core.ACMEOrder, certID string) []core.ACMEOrder {
	out := make([]core.ACMEOrder, 0, len(orders))
	for _, o := range orders {
		if o.CertID != certID {
			out = append(out, o)
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------- 供 M5 续期调度复用 ----------

func (m *Manager) Bus() *core.EventBus             { return m.opt.Bus }
func (m *Manager) Logger() *core.Logger            { return m.opt.Logger }
func (m *Manager) Store() *core.Store              { return m.opt.Store }
func (m *Manager) NowText() string                 { return nowText() }
func (m *Manager) ExpiryOf(s string) (int, string) { return expiryOf(s) }
func (m *Manager) FmtTime(t time.Time) string      { return t.Format(time.RFC3339) }
