package acme

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"

	"fngate/core"
)

// ProviderField 描述界面上需要填写的凭据字段（值本身只落 secrets/）。
type ProviderField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
}

type ProviderSpec struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Hint   string          `json:"hint"`
	Fields []ProviderField `json:"fields"`
}

func ProviderSpecs() []ProviderSpec {
	return []ProviderSpec{
		{
			Type: "alidns", Name: "阿里云 DNS", Hint: "需要具有 DNS 解析管理权限的 AccessKey",
			Fields: []ProviderField{
				{Key: "access_key", Label: "AccessKey ID", Placeholder: "LTAI…", Required: true, Secret: true},
				{Key: "secret_key", Label: "AccessKey Secret", Placeholder: "••••••••", Required: true, Secret: true},
				{Key: "security_token", Label: "STS Token（可选）", Placeholder: "仅临时凭证需要", Required: false, Secret: true},
				{Key: "region_id", Label: "Region ID（可选）", Placeholder: "cn-hangzhou", Required: false, Secret: false},
			},
		},
		{
			Type: "dnspod", Name: "腾讯云 DNSPod", Hint: "在 DNSPod 控制台创建 API Token，填写「ID,Token」",
			Fields: []ProviderField{
				{Key: "api_key", Label: "DNSPOD_API_KEY", Placeholder: "12345,abcdef…", Required: true, Secret: true},
			},
		},
		{
			Type: "cloudflare", Name: "Cloudflare", Hint: "推荐 API Token（Zone:Read + DNS:Edit）",
			Fields: []ProviderField{
				{Key: "api_token", Label: "DNS API Token（推荐）", Placeholder: "••••••••", Required: false, Secret: true},
				{Key: "zone_token", Label: "Zone API Token（可选）", Placeholder: "••••••••", Required: false, Secret: true},
				{Key: "email", Label: "账户邮箱（旧式 Global API Key）", Placeholder: "name@example.com", Required: false, Secret: false},
				{Key: "api_key", Label: "Global API Key", Placeholder: "••••••••", Required: false, Secret: true},
			},
		},
		{
			Type: "manual", Name: "手动添加 TXT 记录", Hint: "无需 API 凭据；申请时展示 TXT 记录，添加后点「我已添加」或等待自动探测生效",
			Fields: []ProviderField{},
		},
	}
}

type credentials map[string]string

func (c credentials) get(k string) string { return strings.TrimSpace(c[k]) }

type dnsBundle struct {
	provider challenge.Provider
	opts     []dns01.ChallengeOption
	manual   *manualProvider
	// checkNote 记录本次传播校验采用的策略，写入订单日志便于排查。
	checkNote string
}

// providerWithTimeout 覆盖 provider 自带的等待时长，用于「传播检查最长等待」设置项。
type providerWithTimeout struct {
	challenge.Provider
	timeout  time.Duration
	interval time.Duration
}

func (p *providerWithTimeout) Timeout() (time.Duration, time.Duration) {
	return p.timeout, p.interval
}

// preflighter 是可选能力：写入前先只读核对域名是否真托管在该账号。
type preflighter interface {
	Preflight([]string) (string, error)
}

// Preflight 必须显式透传：内嵌的是 challenge.Provider 接口，方法集里没有 Preflight，
// 不转发的话外层的类型断言会失败，预检被静默跳过（用户直到 CA 下单后才发现域名不在账号下）。
func (p *providerWithTimeout) Preflight(domains []string) (string, error) {
	if pf, ok := p.Provider.(preflighter); ok {
		return pf.Preflight(domains)
	}
	return "", nil
}

// dnsChallengeOptions 依据设置与域名实际委派情况，决定传播校验策略。
//
// 关键点：lego 默认要求先列出 zone apex 的权威 NS。DNSPod 免费版对 apex 的
// NS 查询返回空 Answer（只有 authority 段 SOA），lego 会一直等到超时并抛出
// "could not determine authoritative nameservers"。这里在提交 CA 之前就探测清楚，
// 该降级就降级，避免用户白等两分钟还看不懂原因。
func (m *Manager) dnsChallengeOptions(domains []string, orderID string) (dnsCheckPlan, []dns01.ChallengeOption) {
	st := m.store.Snapshot().Settings
	mode := strings.TrimSpace(st.DNSCheckMode)
	if mode == "" {
		mode = dnsCheckAuto
	}
	plan, err := planDNSCheck(domains, mode, st.DNSResolvers)
	if err != nil {
		// 探测不出来（域名委派异常，或本机 DNS 不可用）时不让流程直接中断：
		// 交给 lego 自己的检查决定，但降级为递归校验并把原因写进日志，避免空等。
		m.appendLog(orderID, "DNS 预检提示："+err.Error())
		plan = dnsCheckPlan{
			Mode:      dnsCheckRecursive,
			Zone:      plan.Zone,
			Resolvers: effectiveResolvers(st.DNSResolvers),
			Reason:    "预检未完成，已降级为递归解析校验",
		}
	}

	opts := make([]dns01.ChallengeOption, 0, 3)
	if len(plan.Resolvers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(plan.Resolvers))
	}
	if plan.Mode == dnsCheckRecursive {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	return plan, opts
}

func (m *Manager) buildDNS(p core.DNSProvider, orderID string, domains []string) (*dnsBundle, error) {
	switch p.Type {
	case "manual":
		mp := &manualProvider{
			m: m, orderID: orderID,
			timeout: 30 * time.Minute, interval: m.manualInterval,
		}
		return &dnsBundle{
			provider: mp,
			manual:   mp,
			opts: []dns01.ChallengeOption{
				dns01.DisableAuthoritativeNssPropagationRequirement(),
				mp.preCheck(),
			},
		}, nil
	case "alidns", "dnspod", "cloudflare":
	default:
		return nil, fmt.Errorf("不支持的 DNS 服务商：%s", p.Type)
	}
	if p.CredentialRef == "" {
		return nil, fmt.Errorf("DNS 凭据未配置，请重新保存该服务商的凭据")
	}
	raw, err := m.store.SecretRead(p.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("读取 DNS 凭据失败（可能从备份恢复后凭据丢失）：%w", err)
	}
	var cred credentials
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("DNS 凭据格式损坏：%w", err)
	}

	st := m.store.Snapshot().Settings
	plan, opts := m.dnsChallengeOptions(domains, orderID)
	wait := time.Duration(st.DNSWaitSec) * time.Second
	if wait <= 0 {
		wait = dns01.DefaultPropagationTimeout
	}
	// wrap 统一套上「传播检查最长等待」，并按需降级权威 NS 校验。
	wrap := func(pr challenge.Provider) challenge.Provider {
		return &providerWithTimeout{Provider: pr, timeout: wait, interval: dns01.DefaultPollingInterval}
	}
	build := func(pr challenge.Provider) *dnsBundle {
		return &dnsBundle{provider: wrap(pr), opts: opts, checkNote: describeCheckPlan(plan)}
	}

	switch p.Type {
	case "alidns":
		cfg := alidns.NewDefaultConfig()
		cfg.APIKey = cred.get("access_key")
		cfg.SecretKey = cred.get("secret_key")
		cfg.SecurityToken = cred.get("security_token")
		if r := cred.get("region_id"); r != "" {
			cfg.RegionID = r
		}
		if cfg.APIKey == "" || cfg.SecretKey == "" {
			return nil, fmt.Errorf("阿里云 DNS 缺少 AccessKey ID / Secret")
		}
		pr, err := alidns.NewDNSProviderConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("初始化阿里云 DNS 失败：%w", err)
		}
		return build(pr), nil

	case "dnspod":
		token := cred.get("api_key")
		if token == "" {
			return nil, fmt.Errorf("DNSPod 缺少 API Key（格式通常为 ID,Token）")
		}
		if !strings.Contains(token, ",") {
			return nil, fmt.Errorf("DNSPod API Token 格式应为「ID,Token」，两段用英文逗号分隔")
		}
		// 用自研 provider：lego 那份只取域名列表第一页，且会吞掉 DNSPod 的错误码。
		pr := newDNSPodProvider(token, 600, m.orderLogger(orderID))
		pr.resolvers = effectiveResolvers(st.DNSResolvers)
		return build(pr), nil

	case "cloudflare":
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthToken = cred.get("api_token")
		cfg.ZoneToken = cred.get("zone_token")
		cfg.AuthEmail = cred.get("email")
		cfg.AuthKey = cred.get("api_key")
		if cfg.AuthToken == "" && (cfg.AuthEmail == "" || cfg.AuthKey == "") {
			return nil, fmt.Errorf("Cloudflare 需要 DNS API Token，或同时提供邮箱与 Global API Key")
		}
		pr, err := cloudflare.NewDNSProviderConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("初始化 Cloudflare 失败：%w", err)
		}
		return build(pr), nil
	}
	return nil, fmt.Errorf("不支持的 DNS 服务商：%s", p.Type)
}

// manualProvider 不阻塞 Present：所有 TXT 记录会一次性登记到订单里，
// 之后由 lego 自带的 DNS 传播轮询等待生效；用户点「我已添加」可跳过轮询。
type manualProvider struct {
	m         *Manager
	orderID   string
	timeout   time.Duration
	interval  time.Duration
	confirmed atomic.Bool
	canceled  atomic.Bool
}

func (p *manualProvider) Present(domain, token, keyAuth string) error {
	if p.canceled.Load() {
		return fmt.Errorf("任务已取消")
	}
	info := dns01.GetChallengeInfo(domain, keyAuth)
	// 手动模式同样要跟随 CNAME：带 CNAME 的名字上写 TXT 是无效的，用户照着填也过不了。
	target := resolveChallengeName(domain, effectiveResolvers(p.m.store.Snapshot().Settings.DNSResolvers))
	if target.Followed() {
		p.m.appendLog(p.orderID, fmt.Sprintf("%s 存在 CNAME → %s，TXT 需添加在 %s 上（该名字上的 TXT 会被解析器忽略）",
			target.Query, target.Target, target.Target))
	}
	p.m.addManualTXT(p.orderID, target.Target, info.Value)
	return nil
}

func (p *manualProvider) CleanUp(domain, token, keyAuth string) error {
	// 记录保留到订单结束，由 Manager 统一清理；此处不做 DNS 写入。
	return nil
}

func (p *manualProvider) Timeout() (time.Duration, time.Duration) {
	timeout, interval := p.timeout, p.interval
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return timeout, interval
}

func (p *manualProvider) preCheck() dns01.ChallengeOption {
	return dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
		if p.canceled.Load() {
			return false, fmt.Errorf("任务已取消")
		}
		if p.confirmed.Load() {
			return true, nil
		}
		return check(fqdn, value)
	})
}
