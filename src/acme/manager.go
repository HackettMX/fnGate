package acme

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"

	"fngate/cert"
	"fngate/core"
)

type runHandle struct {
	canceled atomic.Bool
	manual   *manualProvider
}

// Manager 驱动 ACME 订单后台任务与自动续期。
// 所有敏感数据（账户密钥、DNS 凭据）都经 core.Store 的 secrets 通道。
type Manager struct {
	store *core.Store
	bus   *core.EventBus
	log   *core.Logger
	certs *cert.Manager
	sched *core.Scheduler

	queue chan string
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	runs  map[string]*runHandle

	// manualInterval 仅用于测试缩短 DNS 传播轮询间隔；生产保持默认 10 秒。
	manualInterval time.Duration
}

type Deps struct {
	Store     *core.Store
	Bus       *core.EventBus
	Logger    *core.Logger
	Scheduler *core.Scheduler
	Certs     *cert.Manager
}

func New(d Deps) *Manager {
	if d.Bus == nil {
		d.Bus = core.NewEventBus()
	}
	m := &Manager{
		store: d.Store, bus: d.Bus, log: d.Logger, certs: d.Certs, sched: d.Scheduler,
		queue: make(chan string, 128), done: make(chan struct{}), runs: map[string]*runHandle{},
	}
	m.recoverStaleOrders()
	if d.Scheduler != nil {
		d.Scheduler.Every("acme.tick", 15*time.Second, m.tick)
	}
	go m.worker()
	return m
}

func (m *Manager) Close() {
	m.once.Do(func() { close(m.done) })
}

func (m *Manager) worker() {
	for {
		select {
		case <-m.done:
			return
		case id := <-m.queue:
			m.runOrder(id)
		}
	}
}

func (m *Manager) enqueue(id string) {
	select {
	case m.queue <- id:
	case <-m.done:
	default:
		_ = m.setStatus(id, "failed", "任务队列已满，请稍后重试")
	}
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func nowText() string { return time.Now().Format("2006-01-02 15:04:05") }

func (m *Manager) publish(level, format string, args ...interface{}) {
	if m.bus != nil {
		m.bus.Publish("acme", level, format, args...)
	}
}

func (m *Manager) logf(format string, args ...interface{}) {
	if m.log != nil {
		m.log.Info("[acme] "+format, args...)
	}
}

// ---------- 状态读写 ----------

func (m *Manager) order(id string) (core.ACMEOrder, bool) {
	for _, o := range m.store.Snapshot().ACMEOrders {
		if o.ID == id {
			return o, true
		}
	}
	return core.ACMEOrder{}, false
}

func (m *Manager) mutateOrder(id string, fn func(*core.ACMEOrder) error) error {
	return m.store.Update(func(st *core.State) error {
		for i := range st.ACMEOrders {
			if st.ACMEOrders[i].ID == id {
				st.ACMEOrders[i].UpdatedAt = nowText()
				return fn(&st.ACMEOrders[i])
			}
		}
		return fmt.Errorf("任务不存在")
	})
}

func (m *Manager) appendLog(id, line string) {
	_ = m.mutateOrder(id, func(o *core.ACMEOrder) error {
		o.Logs = append(o.Logs, nowText()+" "+line)
		if len(o.Logs) > 200 {
			o.Logs = append([]string(nil), o.Logs[len(o.Logs)-200:]...)
		}
		return nil
	})
}

// orderLogger 把 DNS 服务商侧的细节写进任务日志。排查「写入 TXT 失败」时，
// 「域名匹配到哪个 zone、写了哪条记录、服务商原话是什么」比任何总结性文案都有用。
func (m *Manager) orderLogger(orderID string) func(string, ...interface{}) {
	if orderID == "" {
		return nil
	}
	return func(format string, args ...interface{}) {
		m.appendLog(orderID, fmt.Sprintf(format, args...))
	}
}

func (m *Manager) setStatus(id, status, line string) error {
	return m.mutateOrder(id, func(o *core.ACMEOrder) error {
		o.Status = status
		if line != "" {
			o.Logs = append(o.Logs, nowText()+" "+line)
			if len(o.Logs) > 200 {
				o.Logs = append([]string(nil), o.Logs[len(o.Logs)-200:]...)
			}
		}
		return nil
	})
}

func (m *Manager) addManualTXT(orderID, name, value string) {
	_ = m.mutateOrder(orderID, func(o *core.ACMEOrder) error {
		for _, r := range o.ManualTXT {
			if r.Domain == name && r.Value == value {
				return nil
			}
		}
		o.ManualTXT = append(o.ManualTXT, core.TXTRecord{Domain: name, Value: value})
		o.Status = "waiting_dns"
		o.Logs = append(o.Logs, nowText()+" 待添加 TXT 记录 "+name+" = "+value)
		return nil
	})
	m.publish("info", "任务 %s 需要手动添加 TXT 记录：%s", orderID[:minInt(8, len(orderID))], name)
}

func (m *Manager) clearManualTXT(orderID string) {
	_ = m.mutateOrder(orderID, func(o *core.ACMEOrder) error {
		o.ManualTXT = nil
		return nil
	})
}

func (m *Manager) setRun(id string, h *runHandle) {
	m.mu.Lock()
	m.runs[id] = h
	m.mu.Unlock()
}
func (m *Manager) getRun(id string) *runHandle {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[id]
}
func (m *Manager) delRun(id string) {
	m.mu.Lock()
	delete(m.runs, id)
	m.mu.Unlock()
}

func (m *Manager) recoverStaleOrders() {
	_ = m.store.Update(func(st *core.State) error {
		for i := range st.ACMEOrders {
			o := &st.ACMEOrders[i]
			switch o.Status {
			case "pending", "waiting_dns", "validating", "issuing":
				o.Status = "failed"
				o.Error = "应用重启导致任务中断，请点击「重试」重新发起"
				o.Logs = append(o.Logs, nowText()+" 任务因应用重启而中断")
				o.ManualTXT = nil
				o.UpdatedAt = nowText()
			}
		}
		return nil
	})
}

// ---------- 订单创建 ----------

type OrderPayload struct {
	Domains      []string `json:"domains"`
	ProviderID   string   `json:"provider_id"`
	AccountID    string   `json:"account_id"`
	CA           string   `json:"ca"`
	DirectoryURL string   `json:"directory_url"`
	Email        string   `json:"email"`
	EABKID       string   `json:"eab_kid"`
	EABHMAC      string   `json:"eab_hmac"`
	KeyType      string   `json:"key_type"`
	AutoRenew    *bool    `json:"auto_renew"`
	CertID       string   `json:"cert_id"`
	AccountName  string   `json:"account_name"`
}

func normalizeDomains(raw []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range raw {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if seen[d] {
			continue
		}
		if len(d) > 253 || strings.ContainsAny(d, " /\\:;@&?=") {
			return nil, fmt.Errorf("域名不合法：%s", d)
		}
		check := strings.TrimPrefix(d, "*.")
		if check == "" || strings.HasPrefix(check, "*") || strings.Contains(check, "*") {
			return nil, fmt.Errorf("泛域名只能写成 *.example.com：%s", d)
		}
		parts := strings.Split(check, ".")
		if len(parts) < 2 {
			return nil, fmt.Errorf("域名需要包含至少两段，例如 example.com：%s", d)
		}
		for _, p := range parts {
			if p == "" || strings.HasPrefix(p, "-") || strings.HasSuffix(p, "-") {
				return nil, fmt.Errorf("域名段不合法：%s", d)
			}
			for _, ch := range p {
				if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
					return nil, fmt.Errorf("域名含有非法字符：%s", d)
				}
			}
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请至少填写一个域名")
	}
	if len(out) > 20 {
		return nil, fmt.Errorf("一张证书最多包含 20 个域名")
	}
	// 主域名放首位，泛域名随后，便于证书 CN 取非泛域名。
	sort.SliceStable(out, func(i, j int) bool {
		wi, wj := strings.HasPrefix(out[i], "*."), strings.HasPrefix(out[j], "*.")
		return !wi && wj
	})
	return out, nil
}

func (m *Manager) findProvider(id string) (core.DNSProvider, error) {
	for _, p := range m.store.Snapshot().DNSProviders {
		if p.ID == id {
			return p, nil
		}
	}
	return core.DNSProvider{}, fmt.Errorf("DNS 服务商不存在，请先在「域名解析」页添加 DNS 服务商")
}

func (m *Manager) findAccount(id string) (core.ACMEAccount, error) {
	for _, a := range m.store.Snapshot().ACMEAccounts {
		if a.ID == id {
			return a, nil
		}
	}
	return core.ACMEAccount{}, fmt.Errorf("ACME 账户不存在")
}

// ensureAccount 允许不预建账户直接申请：按 CA 复用或隐式创建，降低首次使用门槛。
func (m *Manager) ensureAccount(p OrderPayload) (core.ACMEAccount, error) {
	st := m.store.Snapshot()
	if p.AccountID != "" {
		return m.findAccount(p.AccountID)
	}
	ca := p.CA
	if ca == "" {
		ca = CALetsEncrypt
	}
	for _, a := range st.ACMEAccounts {
		if a.CA == ca {
			return a, nil
		}
	}
	dir, err := DirectoryURL(ca, p.DirectoryURL)
	if err != nil {
		return core.ACMEAccount{}, err
	}
	acc := core.ACMEAccount{
		ID: newID(), CA: ca, DirectoryURL: dir, Email: strings.TrimSpace(p.Email),
		EABKID: strings.TrimSpace(p.EABKID), EABHMAC: strings.TrimSpace(p.EABHMAC),
		CreatedAt: nowText(),
	}
	if p.DirectoryURL != "" || ca == CACustom {
		acc.DirectoryURL = dir
	}
	name := strings.TrimSpace(p.AccountName)
	if name == "" {
		name = ca
	}
	if err := m.store.Update(func(s *core.State) error {
		s.ACMEAccounts = append(s.ACMEAccounts, acc)
		return nil
	}); err != nil {
		return core.ACMEAccount{}, err
	}
	m.publish("info", "已创建 ACME 账户 %s（%s）", name, ca)
	return acc, nil
}

// CreateOrder 建立并排队一个签发任务（新申请或指定 cert_id 的续期）。
func (m *Manager) CreateOrder(p OrderPayload) (core.ACMEOrder, error) {
	domains, err := normalizeDomains(p.Domains)
	if err != nil {
		return core.ACMEOrder{}, err
	}
	provider, err := m.findProvider(p.ProviderID)
	if err != nil {
		return core.ACMEOrder{}, err
	}
	acc, err := m.ensureAccount(p)
	if err != nil {
		return core.ACMEOrder{}, err
	}
	keyType := strings.ToLower(strings.TrimSpace(p.KeyType))
	if keyType == "" {
		keyType = "ec256"
	}
	if keyType != "ec256" && keyType != "rsa2048" {
		return core.ACMEOrder{}, fmt.Errorf("证书密钥类型只能是 ec256 或 rsa2048")
	}
	autoRenew := true
	if p.AutoRenew != nil {
		autoRenew = *p.AutoRenew
	}
	if p.CertID != "" {
		if _, ok := m.certs.ByID(p.CertID); !ok {
			return core.ACMEOrder{}, fmt.Errorf("待续期证书不存在")
		}
		if m.hasActiveOrder(p.CertID) {
			return core.ACMEOrder{}, fmt.Errorf("该证书已有进行中的任务")
		}
	}
	o := core.ACMEOrder{
		ID: newID(), CertID: p.CertID, Domains: domains, Status: "pending",
		Challenge: "dns-01", ProviderID: provider.ID, AccountID: acc.ID,
		CA: acc.CA, DirectoryURL: acc.DirectoryURL, KeyType: keyType, AutoRenew: autoRenew,
		Logs:      []string{nowText() + " 任务已创建，域名：" + strings.Join(domains, ", ")},
		CreatedAt: nowText(), UpdatedAt: nowText(),
	}
	if err := m.store.Update(func(st *core.State) error {
		st.ACMEOrders = append(st.ACMEOrders, o)
		if len(st.ACMEOrders) > 100 {
			st.ACMEOrders = append([]core.ACMEOrder(nil), st.ACMEOrders[len(st.ACMEOrders)-100:]...)
		}
		return nil
	}); err != nil {
		return core.ACMEOrder{}, err
	}
	m.publish("info", "已创建证书申请任务：%s（%s）", strings.Join(domains, ", "), provider.Name)
	m.enqueue(o.ID)
	return o, nil
}

func (m *Manager) hasActiveOrder(certID string) bool {
	for _, o := range m.store.Snapshot().ACMEOrders {
		if o.CertID == certID && (o.Status == "pending" || o.Status == "waiting_dns" || o.Status == "validating" || o.Status == "issuing") {
			return true
		}
	}
	return false
}

// RenewNow 为已有 ACME 证书手工触发一次续期。
func (m *Manager) RenewNow(certID string) (core.ACMEOrder, error) {
	c, ok := m.certs.ByID(certID)
	if !ok {
		return core.ACMEOrder{}, fmt.Errorf("证书不存在")
	}
	if c.Source != "acme" || c.ACME == nil {
		return core.ACMEOrder{}, fmt.Errorf("只有 ACME 证书可以申请续期")
	}
	if m.hasActiveOrder(certID) {
		return core.ACMEOrder{}, fmt.Errorf("该证书已有进行中的任务")
	}
	acc, err := m.findAccount(c.ACME.AccountID)
	if err != nil {
		// 备份恢复后账户可能丢失，按 CA 挑一个可用的。
		acc, err = m.ensureAccount(OrderPayload{CA: c.ACME.CA, DirectoryURL: c.ACME.DirectoryURL})
		if err != nil {
			return core.ACMEOrder{}, err
		}
	}
	return m.CreateOrder(OrderPayload{
		Domains: c.SANs, ProviderID: c.ACME.ProviderID, AccountID: acc.ID,
		CA: acc.CA, DirectoryURL: acc.DirectoryURL, KeyType: c.ACME.KeyType,
		AutoRenew: &c.ACME.AutoRenew, CertID: certID,
	})
}

// ---------- 订单执行 ----------

func (m *Manager) runOrder(id string) {
	o, ok := m.order(id)
	if !ok || o.Status != "pending" {
		return
	}
	h := &runHandle{}
	m.setRun(id, h)
	defer func() {
		if h.manual != nil {
			m.clearManualTXT(id)
		}
		m.delRun(id)
	}()

	_ = m.setStatus(id, "validating", "开始连接 ACME 服务并准备 DNS-01 验证")
	acc, err := m.findAccount(o.AccountID)
	if err != nil {
		m.failOrder(id, err)
		return
	}
	provider, err := m.findProvider(o.ProviderID)
	if err != nil {
		m.failOrder(id, err)
		return
	}
	u, err := m.loadUser(acc)
	if err != nil {
		m.failOrder(id, err)
		return
	}
	dir, err := DirectoryURL(acc.CA, acc.DirectoryURL)
	if err != nil {
		m.failOrder(id, err)
		return
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = dir
	cfg.UserAgent = "fnGate/1.0"
	if o.KeyType == "rsa2048" {
		cfg.Certificate.KeyType = certcrypto.RSA2048
	} else {
		cfg.Certificate.KeyType = certcrypto.EC256
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		m.failOrder(id, fmt.Errorf("初始化 ACME 客户端失败：%w", err))
		return
	}
	m.appendLog(id, fmt.Sprintf("ACME Directory：%s", trimURL(dir)))
	if err := m.registerIfNeeded(client, u, acc); err != nil {
		m.failOrder(id, err)
		return
	}
	bundle, err := m.buildDNS(provider, id, o.Domains)
	if err != nil {
		m.failOrder(id, err)
		return
	}
	h.manual = bundle.manual
	if bundle.manual != nil {
		// 让「继续验证」能在执行期间找到这个 provider。
		m.setRun(id, h)
	}
	if err := client.Challenge.SetDNS01Provider(bundle.provider, bundle.opts...); err != nil {
		m.failOrder(id, fmt.Errorf("配置 DNS-01 失败：%w", err))
		return
	}
	m.appendLog(id, "DNS 服务商："+provider.Name)
	if bundle.checkNote != "" {
		m.appendLog(id, bundle.checkNote)
	}
	// 先做一次只读预检：域名到底托管在哪个 zone、账号是否真能管到它。
	// 否则 CA 已经下单，才在写入阶段甩出一句含糊的凭据错误。
	if pf, ok := bundle.provider.(preflighter); ok {
		zones, err := pf.Preflight(o.Domains)
		if err != nil {
			m.failOrder(id, err)
			return
		}
		if zones != "" {
			m.appendLog(id, "DNS 托管域："+zones)
		}
	}
	if bundle.manual != nil {
		m.appendLog(id, "请在 DNS 控制台添加下方 TXT 记录，添加后点「我已添加，继续验证」；系统也会自动探测生效")
	} else {
		m.appendLog(id, "正在自动写入 TXT 记录并等待 DNS 生效")
	}
	if h.canceled.Load() {
		return
	}
	_ = m.setStatus(id, "issuing", "已提交 DNS-01 验证，等待 CA 完成校验并签发证书")
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: o.Domains, Bundle: true})
	if err != nil {
		m.failOrder(id, err)
		return
	}
	if h.canceled.Load() {
		return
	}
	if o, ok := m.order(id); ok && o.Status == "canceled" {
		return
	}
	certPEM := append([]byte(nil), res.Certificate...)
	if len(res.IssuerCertificate) > 0 && !bytes.Contains(certPEM, bytes.TrimSpace(res.IssuerCertificate)) {
		certPEM = append(certPEM, '\n')
		certPEM = append(certPEM, res.IssuerCertificate...)
	}
	keyPEM := res.PrivateKey
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		m.failOrder(id, fmt.Errorf("CA 返回的证书或私钥为空"))
		return
	}
	meta := &core.ACMEMeta{
		CA: acc.CA, DirectoryURL: acc.DirectoryURL, Challenge: "dns-01",
		ProviderID: o.ProviderID, ManualDNS: provider.Type == "manual",
		AccountID: acc.ID, KeyType: o.KeyType, AutoRenew: o.AutoRenew,
		LastRenewAt: nowText(),
	}
	var certID string
	if o.CertID != "" {
		certID = o.CertID
		if _, err := m.certs.ReplacePair(certID, certPEM, keyPEM, true); err != nil {
			// ReplacePair 内部已回滚旧证书文件。
			m.failOrder(id, fmt.Errorf("写入续期证书失败，旧证书继续服务：%w", err))
			return
		}
		_ = m.certs.MutateCertificate(certID, func(c *core.Certificate) error {
			c.ACME = meta
			return nil
		})
		m.appendLog(id, "续期成功，cert_id 保持不变，引用方零重启生效")
	} else {
		nc, err := m.certs.AddACME(strings.Join(o.Domains, ", "), certPEM, keyPEM, meta)
		if err != nil {
			m.failOrder(id, fmt.Errorf("写入新证书失败：%w", err))
			return
		}
		certID = nc.ID
		m.appendLog(id, "证书已签发并加入证书库，可在 HTTPS 入口中选用")
	}
	_ = m.mutateOrder(id, func(ord *core.ACMEOrder) error {
		ord.Status = "done"
		ord.CertID = certID
		ord.Error = ""
		ord.ManualTXT = nil
		return nil
	})
	m.publish("info", "ACME 证书签发成功：%s", strings.Join(o.Domains, ", "))
	m.logf("order %s done cert=%s", id, certID)
}

func trimURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

func humanizeACMEErr(err error) string {
	if err == nil {
		return ""
	}
	// DNS 服务商自己报的错最有信息量，直接按它的原文 + 建议展示。
	var dpe *dnsProviderError
	if errors.As(err, &dpe) {
		return dpe.Human()
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "rateLimited"), strings.Contains(s, "too many certificates"):
		return "触发 CA 速率限制，请稍后再试；调试阶段建议使用 Staging 环境。"
	case strings.Contains(s, "Incorrect TXT"), strings.Contains(s, "incorrect validation certificate"),
		strings.Contains(s, "No TXT record found"), strings.Contains(s, "no TXT record"):
		return "CA 在 _acme-challenge 上读不到预期的 TXT。该名字若被 CNAME 指向别处（常见于 * 通配记录），" +
			"CA 只会去 CNAME 的目标名取 TXT，写在带 CNAME 的名字上会被忽略。" +
			"请到「域名解析 → 一键体检」查看 _acme-challenge 的 CNAME 落点，并确认 TXT 已写在该目标名上；" +
			"订单日志里有一行「TXT 落点」会写明本次实际写入的位置。"
	case strings.Contains(s, "unauthorized"):
		return "CA 拒绝了这个域名的验证：通常是 TXT 记录未生效或被同名 CNAME 覆盖，请到「域名解析 → 一键体检」核对 _acme-challenge 的落点。"
	case strings.Contains(s, "NXDOMAIN"), strings.Contains(s, "no such host"), strings.Contains(s, "DNS problem"):
		return "域名或 _acme-challenge 记录解析失败，请确认域名已正确解析。"
	case strings.Contains(s, "error presenting token"), strings.Contains(s, "API call failed"),
		strings.Contains(s, "API call has failed"):
		// 关键：不要把这层包装连同里面的真实原因一起丢掉。
		if detail := providerErrDetail(s); detail != "" {
			return "写入 DNS TXT 记录失败：" + detail
		}
		return "写入 DNS TXT 记录失败，请检查 API 凭据是否有效且具备 DNS 编辑权限。"
	case strings.Contains(s, "no subdomain because the domain and the zone are identical"):
		// lego 其他 provider 在「_acme-challenge 被 CNAME 带到主域名」时只会抛这句英文。
		return "TXT 记录需要写在根域名上（_acme-challenge 被 CNAME 指到了主域名）：请改用 DNSPod / Cloudflare 服务商，或删除 DNS 里的 * 通配 CNAME"
	case strings.Contains(s, "could not determine authoritative nameservers"):
		return "该域名的 DNS 不返回区域顶点的 NS 记录（DNSPod 免费版常见），导致无法确认 TXT 是否已传播。" +
			"请在「设置 → DNS 传播校验」选择「自动」或「递归解析」后重试；TXT 记录本身通常是写对了的。"
	case strings.Contains(s, "time limit exceeded"):
		return "等待 TXT 记录生效超时。请在订单日志查看「传播校验」那行的区域与记录名，" +
			"确认 TXT 写在了 CA 要查的名字下（被 CNAME 带走时会写到主域名），或在设置里延长「传播检查最长等待」后重试。"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"), strings.Contains(s, "timed out"):
		return "连接 ACME 服务或等待 DNS 生效超时，请检查网络与 DNS 传播后重试。"
	case strings.Contains(s, "connection refused"), strings.Contains(s, "dial tcp"):
		return "无法连接 ACME Directory，请检查自定义地址与外网连通性。"
	case strings.Contains(s, "EAB"), strings.Contains(s, "external account"):
		return "该 CA 需要 EAB 外部账户绑定，请在账户配置里填写 KID 与 HMAC。"
	case strings.Contains(s, "任务已取消"):
		return "任务已取消。"
	}
	return s
}

// providerErrDetail 剥掉 lego / dnspod-go 的层层包装，只留最内层的服务商原话。
func providerErrDetail(raw string) string {
	s := strings.TrimSpace(raw)
	markers := []string{
		"error presenting token: ", "API call has failed: ", "API call failed: ",
		"could not get domains: ", "acme: ",
	}
	for changed := true; changed; {
		changed = false
		for _, mk := range markers {
			if i := strings.Index(s, mk); i >= 0 {
				if next := strings.TrimSpace(s[i+len(mk):]); next != "" {
					s = next
					changed = true
				}
			}
		}
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func backoff(failCount int) time.Duration {
	switch {
	case failCount <= 1:
		return time.Hour
	case failCount == 2:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func (m *Manager) failOrder(id string, cause error) {
	if h := m.getRun(id); h != nil && h.canceled.Load() {
		return // 已取消的任务不再覆盖成失败
	}
	msg := humanizeACMEErr(cause)
	raw := strings.TrimSpace(cause.Error())
	if len(raw) > 1200 {
		raw = raw[:1200] + "…"
	}
	_ = m.mutateOrder(id, func(o *core.ACMEOrder) error {
		o.Status = "failed"
		o.Error = msg
		o.ManualTXT = nil
		o.Logs = append(o.Logs, nowText()+" 失败："+msg)
		// 原始错误一律留在日志里：服务商错误码、HTTP 状态、包装链路都在里面，
		// 归纳后的一句话只适合给人看，不适合拿来排查。
		if raw != "" && raw != msg {
			o.Logs = append(o.Logs, nowText()+" 错误详情："+raw)
		}
		if len(o.Logs) > 200 {
			o.Logs = append([]string(nil), o.Logs[len(o.Logs)-200:]...)
		}
		return nil
	})
	if o, ok := m.order(id); ok && o.CertID != "" {
		_ = m.certs.MutateCertificate(o.CertID, func(c *core.Certificate) error {
			if c.ACME == nil {
				c.ACME = &core.ACMEMeta{}
			}
			c.ACME.FailCount++
			c.ACME.LastError = msg
			c.ACME.NextRenewAt = time.Now().Add(backoff(c.ACME.FailCount)).Format(time.RFC3339)
			return nil
		})
	}
	m.publish("error", "证书申请失败：%s", msg)
	m.logf("order %s failed: %v", id, cause)
}

// ---------- 任务控制 ----------

func (m *Manager) Cancel(id string) error {
	h := m.getRun(id)
	if h == nil {
		return fmt.Errorf("任务当前未在运行")
	}
	h.canceled.Store(true)
	if h.manual != nil {
		h.manual.canceled.Store(true)
	}
	return m.setStatus(id, "canceled", "用户取消了任务")
}

func (m *Manager) ConfirmTXT(id string) error {
	h := m.getRun(id)
	if h == nil || h.manual == nil {
		return fmt.Errorf("该任务不是等待手动 TXT 的状态，或已结束")
	}
	h.manual.confirmed.Store(true)
	return m.setStatus(id, "validating", "用户确认已添加 TXT 记录，跳过等待直接校验")
}

func (m *Manager) Retry(id string) error {
	o, ok := m.order(id)
	if !ok {
		return fmt.Errorf("任务不存在")
	}
	if o.Status != "failed" && o.Status != "canceled" {
		return fmt.Errorf("只有失败或已取消的任务可以重试")
	}
	if err := m.mutateOrder(id, func(x *core.ACMEOrder) error {
		x.Status = "pending"
		x.Error = ""
		x.ManualTXT = nil
		return nil
	}); err != nil {
		return err
	}
	if o.CertID != "" {
		_ = m.certs.MutateCertificate(o.CertID, func(c *core.Certificate) error {
			if c.ACME != nil {
				c.ACME.NextRenewAt = ""
			}
			return nil
		})
	}
	m.enqueue(id)
	return nil
}

func (m *Manager) DeleteOrder(id string) error {
	if h := m.getRun(id); h != nil {
		h.canceled.Store(true)
		if h.manual != nil {
			h.manual.canceled.Store(true)
		}
		return fmt.Errorf("任务正在运行，请先取消")
	}
	return m.store.Update(func(st *core.State) error {
		kept := make([]core.ACMEOrder, 0, len(st.ACMEOrders))
		for _, o := range st.ACMEOrders {
			if o.ID != id {
				kept = append(kept, o)
			}
		}
		st.ACMEOrders = kept
		return nil
	})
}

// ---------- 自动续期 ----------

func (m *Manager) tick() {
	st := m.store.Snapshot()
	for _, c := range st.Certificates {
		if c.Source != "acme" || c.ACME == nil || !c.ACME.AutoRenew {
			continue
		}
		days, status := m.certs.ExpiryOf(c.NotAfter)
		if status == "unknown" || days > st.Settings.RenewDays {
			continue
		}
		urgent := days <= 3 || status == "expired"
		if !urgent && time.Now().Hour() < st.Settings.RenewHour {
			continue
		}
		if c.ACME.NextRenewAt != "" {
			if t, err := time.Parse(time.RFC3339, c.ACME.NextRenewAt); err == nil && time.Now().Before(t) {
				continue
			}
		}
		if m.hasActiveOrder(c.ID) {
			continue
		}
		if c.ACME.ProviderID == "" {
			continue
		}
		m.publish("info", "证书「%s」将在 %d 天后到期，开始自动续期", c.Name, days)
		if _, err := m.RenewNow(c.ID); err != nil {
			m.publish("error", "证书「%s」自动续期排队失败：%v", c.Name, err)
			_ = m.certs.MutateCertificate(c.ID, func(x *core.Certificate) error {
				if x.ACME != nil {
					x.ACME.NextRenewAt = time.Now().Add(time.Hour).Format(time.RFC3339)
				}
				return nil
			})
			continue
		}
		// 占位锁：避免下一轮 tick 重复排队；成功后清空，失败按退避覆盖。
		_ = m.certs.MutateCertificate(c.ID, func(x *core.Certificate) error {
			if x.ACME != nil {
				x.ACME.NextRenewAt = time.Now().Add(2 * time.Hour).Format(time.RFC3339)
			}
			return nil
		})
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
