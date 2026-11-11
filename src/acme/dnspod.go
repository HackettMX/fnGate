package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// 为什么不用 lego 自带的 dnspod provider
//
//  1. 它用 Domain.List 取域名，而该接口默认只返回一页（20 条）。账号里域名一多，
//     目标域名就落在后面的分页里，于是 getHostedZone 找不到 zone；
//  2. 它把所有 Present 失败统一包成 "API call failed"，错误码与原始消息全部丢失，
//     界面最后只剩一句「请检查 API 凭据是否有效且具备 DNS 编辑权限」——
//     可真实原因可能是 Token 失效、域名不在账号下、记录已存在、频率超限；
//  3. CleanUp 会删掉该 sub_domain 下所有 TXT 记录。根域 + 泛域名申请时两条挑战
//     记录同名，先清理的那次会把另一次也删掉；用户自己的 TXT 也会被误伤。
//
// 这里自己实现一份：分页查 zone、原样上报 DNSPod 错误码、按记录值精确清理。

const (
	dnspodEndpoint  = "https://dnsapi.cn/"
	dnspodUserAgent = "fnGate/1.0 (fnGate ACME client)"
	dnspodPageSize  = 100
)

// ---------- 错误类型 ----------

// dnsProviderError 保留 DNS 服务商返回的原始错误码与消息，供 humanizeACMEErr 拼出
// 用户能照着做的提示，而不是一句通用文案。
type dnsProviderError struct {
	Provider string
	Action   string
	Code     string
	Message  string
	Hint     string
}

func (e *dnsProviderError) Error() string {
	msg := fmt.Sprintf("%s %s失败：%s", e.Provider, e.Action, e.Message)
	if e.Code != "" && e.Code != "1" {
		msg += "（错误码 " + e.Code + "）"
	}
	return msg
}

// Human 是展示给用户的短句：说清哪一步、服务商原话、以及下一步该做什么。
func (e *dnsProviderError) Human() string {
	head := fmt.Sprintf("%s失败：%s 返回「%s」", e.Action, e.Provider, e.Message)
	if e.Code != "" && e.Code != "1" {
		head += "（" + e.Code + "）"
	}
	if e.Hint != "" {
		return head + "，" + e.Hint
	}
	return head + "，可到服务商配置里点「测试连接」核对凭据"
}

// newDNSPodError 把 DNSPod 的 status.code / status.message 翻译成可执行的建议。
// DNSPod 即使业务失败也返回 HTTP 200，真正的结果在 status.code 里。
func newDNSPodError(action, code, message string) *dnsProviderError {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "未知错误"
	}
	return &dnsProviderError{
		Provider: "DNSPod", Action: action, Code: code, Message: message,
		Hint: dnspodHint(code, message),
	}
}

func dnspodHint(code, msg string) string {
	low := strings.ToLower(msg)
	switch {
	case code == "10004", strings.Contains(msg, "Token"), strings.Contains(low, "token"),
		strings.Contains(msg, "登录失败"), strings.Contains(low, "login"):
		return "API Token 已失效或格式不对（应为「ID,Token」），请到 DNSPod 控制台重新生成后填回"
	case code == "10002", strings.Contains(msg, "频率"), strings.Contains(low, "too many"),
		strings.Contains(low, "rate"):
		return "接口调用过于频繁，请等 1~2 分钟再重试"
	case strings.Contains(msg, "域名不存在"), strings.Contains(low, "domain not exist"):
		return "该域名不在当前 DNSPod 账号下，或未托管在 DNSPod"
	case strings.Contains(msg, "记录已存在"), strings.Contains(msg, "已经存在"),
		strings.Contains(low, "exist"):
		return "已存在同名 TXT 记录，请先到 DNSPod 控制台删除后再重试"
	case strings.Contains(msg, "线路"):
		return "记录线路不可用，请在 DNSPod 控制台确认默认线路名称"
	case strings.Contains(msg, "锁定"), strings.Contains(msg, "暂停"), strings.Contains(msg, "封禁"):
		return "域名处于锁定/暂停状态，请先在 DNSPod 控制台解除"
	case strings.Contains(msg, "权限"), strings.Contains(msg, "无权"), strings.Contains(low, "permission"),
		strings.Contains(low, "forbidden"):
		return "该 Token 不具备解析记录编辑权限，请检查 Token 的授权范围"
	case strings.Contains(msg, "余额"), strings.Contains(msg, "套餐"), strings.Contains(msg, "超出"):
		return "账号套餐或记录数已达上限，请到 DNSPod 控制台处理"
	}
	return ""
}

// ---------- HTTP 客户端 ----------

type dnspodAPI struct {
	token    string
	hc       *http.Client
	endpoint string // 便于测试注入本地 httptest 服务
}

func newDNSPodAPI(token string) *dnspodAPI {
	return &dnspodAPI{
		token:    strings.TrimSpace(token),
		hc:       &http.Client{Timeout: 20 * time.Second},
		endpoint: dnspodEndpoint,
	}
}

type dnspodStatus struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// dnspodAPIError 只承载「接口调通了但业务失败」的情况。
type dnspodAPIError struct {
	Method  string
	Code    string
	Message string
}

func (e *dnspodAPIError) Error() string {
	return fmt.Sprintf("%s: [%s] %s", e.Method, e.Code, e.Message)
}

// emptyResult 判断「列表为空 / 记录已不存在」这类并非错误的结果。
// DNSPod 在记录列表为空时返回 code=10 / message=记录列表为空。
func (e *dnspodAPIError) emptyResult() bool {
	return e.Code == "10" ||
		strings.Contains(e.Message, "为空") ||
		strings.Contains(e.Message, "没有记录") ||
		strings.Contains(e.Message, "记录不存在")
}

func (a *dnspodAPI) call(method string, extra url.Values, out interface{}) error {
	form := url.Values{}
	form.Set("login_token", a.token)
	form.Set("format", "json")
	form.Set("lang", "cn")
	form.Set("error_on_empty", "no")
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}

	req, err := http.NewRequest(http.MethodPost, a.endpoint+method, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// DNSPod 会拒绝 Go 默认 UA，必须带一个可识别的 UA。
	req.Header.Set("User-Agent", dnspodUserAgent)

	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s 返回 HTTP %d", method, resp.StatusCode)
	}

	var env struct {
		Status dnspodStatus `json:"status"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%s 返回了非 JSON 响应（可能被网关或代理拦截）", method)
	}
	if env.Status.Code != "1" {
		return &dnspodAPIError{Method: method, Code: env.Status.Code, Message: strings.TrimSpace(env.Status.Message)}
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("%s 响应解析失败：%w", method, err)
		}
	}
	return nil
}

type dnspodZone struct {
	ID     string
	Name   string
	Status string
}

// listZones 分页拉全账号域名。lego 只取第一页，是「域名明明在账号下却报找不到 zone」的元凶。
func (a *dnspodAPI) listZones() ([]dnspodZone, error) {
	var zones []dnspodZone
	for page := 1; page <= 50; page++ {
		var res struct {
			Domains []struct {
				ID     json.Number `json:"id"`
				Name   string      `json:"name"`
				Status string      `json:"status"`
			} `json:"domains"`
		}
		form := url.Values{}
		form.Set("page", strconv.Itoa(page))
		form.Set("length", strconv.Itoa(dnspodPageSize))
		if err := a.call("Domain.List", form, &res); err != nil {
			var apiErr *dnspodAPIError
			if errors.As(err, &apiErr) && apiErr.emptyResult() {
				return zones, nil
			}
			return nil, err
		}
		for _, d := range res.Domains {
			zones = append(zones, dnspodZone{
				ID:     d.ID.String(),
				Name:   strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Name), ".")),
				Status: d.Status,
			})
		}
		if len(res.Domains) < dnspodPageSize {
			break
		}
	}
	return zones, nil
}

type dnspodRecord struct {
	// DNSPod 的记录 ID 是字符串，域名 ID 是数字，两者不能混用同一个类型。
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (a *dnspodAPI) listTXT(zoneID, sub string) ([]dnspodRecord, error) {
	var res struct {
		Records []dnspodRecord `json:"records"`
	}
	form := url.Values{}
	form.Set("domain_id", zoneID)
	form.Set("sub_domain", sub)
	form.Set("record_type", "TXT")
	if err := a.call("Record.List", form, &res); err != nil {
		var apiErr *dnspodAPIError
		if errors.As(err, &apiErr) && apiErr.emptyResult() {
			return nil, nil
		}
		return nil, err
	}
	return res.Records, nil
}

// listRecordsByType 分页拉取 zone 内某一类型的全部记录。
// 用于在服务商侧判断 _acme-challenge 上是否存在 CNAME（含 * 通配），
// 不依赖本机 DNS——NAS 上的 fake-ip / 广告过滤会改写应答，靠解析器判断并不可靠。
func (a *dnspodAPI) listRecordsByType(zoneID, recordType string) ([]dnspodRecord, error) {
	var out []dnspodRecord
	for page := 0; page < 20; page++ {
		var res struct {
			Records []dnspodRecord `json:"records"`
		}
		form := url.Values{}
		form.Set("domain_id", zoneID)
		form.Set("record_type", recordType)
		form.Set("offset", strconv.Itoa(page*dnspodPageSize))
		form.Set("length", strconv.Itoa(dnspodPageSize))
		if err := a.call("Record.List", form, &res); err != nil {
			var apiErr *dnspodAPIError
			if errors.As(err, &apiErr) && apiErr.emptyResult() {
				return out, nil
			}
			return nil, err
		}
		out = append(out, res.Records...)
		if len(res.Records) < dnspodPageSize {
			break
		}
	}
	return out, nil
}

func (a *dnspodAPI) createTXT(zoneID, sub, value string, ttl int) (string, error) {
	build := func(line string) url.Values {
		form := url.Values{}
		form.Set("domain_id", zoneID)
		form.Set("sub_domain", sub)
		form.Set("record_type", "TXT")
		form.Set("record_line", line)
		form.Set("value", value)
		form.Set("ttl", strconv.Itoa(ttl))
		return form
	}
	var res struct {
		Record struct {
			ID string `json:"id"`
		} `json:"record"`
	}
	err := a.call("Record.Create", build("默认"), &res)
	var apiErr *dnspodAPIError
	if err != nil && errors.As(err, &apiErr) && strings.Contains(apiErr.Message, "线路") {
		// 国际版账号的默认线路叫 Default。
		err = a.call("Record.Create", build("Default"), &res)
	}
	if err != nil {
		return "", err
	}
	return res.Record.ID, nil
}

func (a *dnspodAPI) deleteRecord(zoneID, recordID string) error {
	form := url.Values{}
	form.Set("domain_id", zoneID)
	form.Set("record_id", recordID)
	err := a.call("Record.Remove", form, nil)
	var apiErr *dnspodAPIError
	if err != nil && errors.As(err, &apiErr) && apiErr.emptyResult() {
		return nil // 已经不存在，视作清理成功
	}
	return err
}

// ---------- Challenge Provider ----------

var (
	_ challenge.Provider        = (*dnspodProvider)(nil)
	_ challenge.ProviderTimeout = (*dnspodProvider)(nil)
)

type dnspodProvider struct {
	api *dnspodAPI
	ttl int
	log func(format string, args ...interface{})

	mu    sync.Mutex
	zones []dnspodZone

	// resolvers 用于自行跟随 _acme-challenge 上的 CNAME；为空时取系统 + 公共 DNS。
	resolvers []string
	// lookupCNAME 仅单测使用：返回空串表示该名字没有 CNAME。
	lookupCNAME func(name string) string

	// cnameRecs 缓存每个 zone 的 CNAME 记录，避免同一订单里反复拉取。
	cnameRecs map[string][]dnspodRecord
	// targets 缓存域名 → 挑战记录名，保证 Present / CleanUp 落在同一个名字上。
	targets map[string]challengeTarget
	// visibleWait 控制写入后的自查时长：0 取默认 12 秒，负数表示跳过（单测用）。
	visibleWait time.Duration

	noted map[string]bool
}

func newDNSPodProvider(token string, ttl int, log func(string, ...interface{})) *dnspodProvider {
	if ttl <= 0 {
		ttl = 600
	}
	return &dnspodProvider{api: newDNSPodAPI(token), ttl: ttl, log: log, noted: map[string]bool{}}
}

func (p *dnspodProvider) note(format string, args ...interface{}) {
	if p.log != nil {
		p.log(format, args...)
	}
}

// noteOnce 让同一条说明只写一次（根域 + 泛域名会各触发一次 Present）。
func (p *dnspodProvider) noteOnce(key, format string, args ...interface{}) {
	p.mu.Lock()
	if p.noted == nil {
		p.noted = map[string]bool{}
	}
	done := p.noted[key]
	p.noted[key] = true
	p.mu.Unlock()
	if !done {
		p.note(format, args...)
	}
}

func (p *dnspodProvider) wrap(action string, err error) error {
	var apiErr *dnspodAPIError
	if errors.As(err, &apiErr) {
		return newDNSPodError(action, apiErr.Code, apiErr.Message)
	}
	if hint := networkHint(err); hint != "" {
		return fmt.Errorf("DNSPod %s失败：%s", action, hint)
	}
	return fmt.Errorf("DNSPod %s失败：%w", action, err)
}

func (p *dnspodProvider) loadZones() ([]dnspodZone, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.zones != nil {
		return p.zones, nil
	}
	zones, err := p.api.listZones()
	if err != nil {
		return nil, p.wrap("读取账号域名列表", err)
	}
	if zones == nil {
		zones = []dnspodZone{}
	}
	p.zones = zones
	return zones, nil
}

// zoneOf 用「最长后缀匹配」定位记录所属 zone，不依赖 SOA 查询，避免 DNS 侧异常
// 把问题伪装成「找不到 zone」。
func (p *dnspodProvider) zoneOf(fqdn string) (dnspodZone, error) {
	zones, err := p.loadZones()
	if err != nil {
		return dnspodZone{}, err
	}
	if z, ok := matchZone(fqdn, zones); ok {
		return z, nil
	}
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	// 常见坑：_acme-challenge 上挂了 CNAME（CDN/托管商），TXT 要写到 CNAME 指向的域名。
	if i := strings.Index(name, "."); i > 0 {
		if z, ok := matchZone(name[i+1:], zones); ok {
			return dnspodZone{}, fmt.Errorf(
				"%s 不在该账号的 %s 下：_acme-challenge 上可能存在 CNAME 记录，需要把 TXT 写到 CNAME 指向的域名",
				name, z.Name)
		}
	}
	if len(zones) == 0 {
		return dnspodZone{}, fmt.Errorf("该 DNSPod 账号下没有任何域名，请确认 Token 属于正确的账号")
	}
	return dnspodZone{}, fmt.Errorf("%s 不属于该 DNSPod 账号下的任何域名（账号内共 %d 个域名），请确认域名已添加到此账号并已使用 DNSPod 的 NS",
		name, len(zones))
}

// Preflight 在向 CA 下单前先做只读检查：域名是否真的托管在这个 DNSPod 账号里。
// 这样「域名不在账号下」就不会等到 CA 已经挂上订单才以一句含糊的凭据错误暴露。
func (p *dnspodProvider) Preflight(domains []string) (string, error) {
	zones, err := p.loadZones()
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	var lines []string
	for _, d := range domains {
		name := normalizeApex(d)
		if name == "" {
			continue
		}
		z, ok := matchZone(name, zones)
		if !ok {
			return "", fmt.Errorf("域名 %s 不在这个 DNSPod 账号下（账号内共 %d 个域名）：请确认域名已添加到该账号，且 NS 已切到 DNSPod",
				name, len(zones))
		}
		if z.Status != "" && z.Status != "enable" {
			return "", fmt.Errorf("域名 %s 在 DNSPod 中的状态为 %s，请先到控制台恢复正常解析", z.Name, z.Status)
		}
		if !seen[z.Name] {
			seen[z.Name] = true
			lines = append(lines, fmt.Sprintf("%s（zone %s）", z.Name, z.ID))
		}
		// 下单前就把 CNAME 落点讲清楚：这是 1.2.2 依然失败的地方。
		if ts := p.targetOf(d); ts.Followed() {
			p.noteOnce("preflight-cname:"+ts.Query,
				"注意：%s 存在 CNAME → %s，TXT 落点会改为后者（该名字上的 TXT 会被 CA 忽略）",
				ts.Query, ts.Target)
		}
	}
	return strings.Join(lines, "、"), nil
}

func (p *dnspodProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	target := p.targetOf(domain)

	if target.Followed() {
		if _, err := p.zoneOf(target.Target); err != nil {
			return fmt.Errorf("%s 上有 CNAME 指向 %s，但 %s 不在这个 DNSPod 账号下，无法写入 TXT。"+
				"请把 %s 也托管到该账号，或删除 DNS 里的 * 通配 CNAME",
				target.Query, target.Target, target.Target, target.Target)
		}
		p.noteOnce("challenge-cname:"+target.Query,
			"TXT 落点：%s 有 CNAME（通常是 * 通配记录）→ %s；按 RFC 1034，带 CNAME 的名字上同名 TXT 会被 CA 忽略，TXT 写到 %s",
			target.Query, target.Target, target.Target)
	}
	if err := p.presentAt(target.Target, info.Value); err != nil {
		return err
	}
	if target.Followed() {
		// 目标名已经写好了，仍在查询名上再写一份：lego 的传播检查按 EffectiveFQDN 查，
		// 宽松的递归解析器会直接返回同名 TXT；而 CA 严格跟随 CNAME 去目标名取。
		// 两条路径都覆盖，才不会出现「lego 检查通过、CA 说读不到」。
		if err := p.presentAt(target.Query, info.Value); err != nil {
			p.note("查询名上未写入同名 TXT（不影响 CNAME 落点）：%v", err)
		}
	}
	p.confirmVisible(target.Query, info.Value)
	return nil
}

// targetOf 计算本次挑战应写入的记录名。
//
// 判定顺序：
//  1. 单测注入的 lookupCNAME；
//  2. 服务商记录接口里查 CNAME（含 * 通配）——不依赖本机 DNS，最可靠；
//  3. 前两步都拿不到结论时，才退回本机 DNS 探测。
func (p *dnspodProvider) targetOf(domain string) challengeTarget {
	query := "_acme-challenge." + normalizeApex(domain)
	if t, ok := p.cachedTarget(domain); ok {
		return t
	}

	target := challengeTarget{Query: query, Target: query}
	switch {
	case p.lookupCNAME != nil:
		// 单测注入：直接给定 CNAME 目标，避免打真实 DNS。
		if next := p.lookupCNAME(query); next != "" {
			next = strings.ToLower(strings.TrimSuffix(next, "."))
			target = challengeTarget{Query: query, Target: next, Chain: []string{query, next}}
		}
	default:
		target = p.followCNAME(query)
		if !target.Followed() && len(p.resolvers) > 0 {
			// 服务商侧没有 CNAME 记录（或接口不可用）时，用解析结果兜底。
			if dnsTarget := resolveChallengeName(domain, p.resolvers); dnsTarget.Followed() {
				target = dnsTarget
			}
		}
	}

	p.mu.Lock()
	if p.targets == nil {
		p.targets = map[string]challengeTarget{}
	}
	p.targets[domain] = target
	p.mu.Unlock()
	return target
}

func (p *dnspodProvider) cachedTarget(domain string) (challengeTarget, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.targets[domain]
	return t, ok
}

// followCNAME 在服务商记录里逐跳跟随 CNAME。
func (p *dnspodProvider) followCNAME(query string) challengeTarget {
	self := challengeTarget{Query: query, Target: query}
	cur := query
	seen := map[string]bool{strings.ToLower(query): true}
	var chain []string
	for hop := 0; hop < 8; hop++ {
		next, ok := p.cnameAt(cur)
		if !ok {
			break
		}
		next = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(next), "."))
		if next == "" {
			break
		}
		if seen[next] {
			self.Loop = true
			return self
		}
		seen[next] = true
		chain = append(chain, cur)
		cur = next
	}
	chain = append(chain, cur)
	return challengeTarget{Query: query, Target: cur, Chain: chain}
}

// cnameAt 查 fqdn 上的 CNAME 目标。只看服务商记录，不查 DNS。
func (p *dnspodProvider) cnameAt(fqdn string) (string, bool) {
	zone, err := p.zoneOf(fqdn)
	if err != nil {
		return "", false
	}
	recs, err := p.zoneCNAMEs(zone)
	if err != nil {
		p.noteOnce("cname-list:"+zone.ID, "读取 %s 的 CNAME 记录失败（将退回 DNS 探测）：%v", zone.Name, err)
		return "", false
	}
	return matchCNAMERecord(recs, zone.Name, fqdn)
}

// zoneCNAMEs 拉取并缓存 zone 内全部 CNAME 记录。
func (p *dnspodProvider) zoneCNAMEs(zone dnspodZone) ([]dnspodRecord, error) {
	p.mu.Lock()
	recs, ok := p.cnameRecs[zone.ID]
	p.mu.Unlock()
	if ok {
		return recs, nil
	}
	recs, err := p.api.listRecordsByType(zone.ID, "CNAME")
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.cnameRecs == nil {
		p.cnameRecs = map[string][]dnspodRecord{}
	}
	p.cnameRecs[zone.ID] = recs
	p.mu.Unlock()
	return recs, nil
}

// confirmVisible 在写入后自查一次「CA 视角能否读到」。
// 只是提示，不阻断流程：真正决定成败的仍是 lego 的传播轮询，
// 但把结果写进日志能在失败时直接指出是「写对了没生效」还是「写错了地方」。
func (p *dnspodProvider) confirmVisible(query, value string) {
	if p.visibleWait < 0 {
		return // 单测环境不打真实 DNS
	}
	if len(p.resolvers) == 0 && p.lookupCNAME != nil {
		return // 单测环境不打真实 DNS
	}
	wait := p.visibleWait
	if wait == 0 {
		wait = 12 * time.Second
	}
	resolvers := p.resolvers
	if len(resolvers) == 0 {
		resolvers = effectiveResolvers(nil)
	}
	ok, detail := waitTXTVisible(resolvers, query, value, wait)
	if ok {
		p.note("TXT 记录已可被解析到（%s）：%s", detail, query)
		return
	}
	p.note("提醒：12 秒内未从公共 DNS 读到 %s 的 TXT（%s）。若随后校验失败，请先在「域名解析」页确认该名字的 CNAME 目标。",
		query, detail)
}

// presentAt 把 value 写到 fqdn 对应的 TXT 记录上。
// fqdn 可能等于 zone（_acme-challenge 被 CNAME 带到主域名时就是这样），
// 此时 sub_domain 用 @ 表示根记录——lego 自带 provider 在这一步会直接报错。
func (p *dnspodProvider) presentAt(fqdn, value string) error {
	zone, err := p.zoneOf(fqdn)
	if err != nil {
		return err
	}
	sub := subDomainOf(fqdn, zone.Name)

	existing, err := p.api.listTXT(zone.ID, sub)
	if err != nil {
		return p.wrap("查询 "+fqdn+" 的 TXT 记录", err)
	}
	for _, r := range existing {
		if sameTXTValue(r.Value, value) {
			// 上次失败残留或用户已手工添加：直接复用，不重复创建。
			p.note("TXT 记录已存在，复用：" + fqdn)
			return nil
		}
	}

	if _, err := p.api.createTXT(zone.ID, sub, value, p.ttl); err != nil {
		return p.wrap("写入 TXT 记录 "+fqdn, err)
	}
	p.note("已写入 TXT 记录：" + fqdn)
	return nil
}

func (p *dnspodProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	target := p.targetOf(domain)
	err := p.cleanupAt(target.Target, info.Value)
	if target.Followed() {
		// 旧版本可能把 TXT 写到了带 CNAME 的查询名上，一并清掉。
		if e := p.cleanupAt(target.Query, info.Value); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (p *dnspodProvider) cleanupAt(fqdn, value string) error {
	zone, err := p.zoneOf(fqdn)
	if err != nil {
		return err
	}
	sub := subDomainOf(fqdn, zone.Name)
	records, err := p.api.listTXT(zone.ID, sub)
	if err != nil {
		return p.wrap("查询 "+fqdn+" 的 TXT 记录", err)
	}
	for _, r := range records {
		// 只删与本条挑战值完全相同的记录：同名多值（根域 + 泛域名）与用户自建 TXT 都不能误删。
		if !sameTXTValue(r.Value, value) {
			continue
		}
		if err := p.api.deleteRecord(zone.ID, r.ID); err != nil {
			return p.wrap("清理 TXT 记录 "+fqdn, err)
		}
		p.note("已清理 TXT 记录：" + fqdn)
	}
	return nil
}

func (p *dnspodProvider) Timeout() (time.Duration, time.Duration) {
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

// ---------- 纯函数辅助（单测覆盖） ----------

// sameTXTValue 比较 TXT 值时会容忍 DNSPod 在个别场景下回带的引号与空白。
func sameTXTValue(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			s = s[1 : len(s)-1]
		}
		return strings.TrimSpace(s)
	}
	return norm(a) == norm(b)
}

// matchZone 返回能覆盖 fqdn 的最长 zone。
func matchZone(fqdn string, zones []dnspodZone) (dnspodZone, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	var best dnspodZone
	found := false
	for _, z := range zones {
		if z.Name == "" {
			continue
		}
		if name == z.Name || strings.HasSuffix(name, "."+z.Name) {
			if !found || len(z.Name) > len(best.Name) {
				best, found = z, true
			}
		}
	}
	return best, found
}

// recordOwner 把 DNSPod 记录的 name 字段还原成 FQDN。
// 接口返回的是主机记录（@ 表示根域），文档里也有回带完整域名的情况，两种都兼容。
func recordOwner(name, zone string) string {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if n == "" || n == "@" {
		return zone
	}
	if n == zone || strings.HasSuffix(n, "."+zone) {
		return n
	}
	return n + "." + zone
}

// matchCNAMERecord 在 zone 的 CNAME 记录里找出能覆盖 fqdn 的那一条。
//
// 必须同时处理通配：用户常见配置是「* CNAME 主域名」，它会让
// _acme-challenge.<domain> 也挂上 CNAME。通配按 RFC 1034 只匹配一层标签，
// 所以 *.666086.xyz 能覆盖 _acme-challenge.666086.xyz，却覆盖不了 a.b.666086.xyz。
func matchCNAMERecord(recs []dnspodRecord, zone, fqdn string) (string, bool) {
	target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	// 精确记录优先：同名既有显式 CNAME 又有 * 通配时，显式的那条才是权威答案。
	for _, r := range recs {
		if !strings.EqualFold(r.Type, "CNAME") || strings.TrimSpace(r.Value) == "" {
			continue
		}
		if recordOwner(r.Name, zone) == target {
			return r.Value, true
		}
	}
	for _, r := range recs {
		if !strings.EqualFold(r.Type, "CNAME") || strings.TrimSpace(r.Value) == "" {
			continue
		}
		owner := recordOwner(r.Name, zone)
		if !strings.HasPrefix(owner, "*.") {
			continue
		}
		suffix := owner[2:]
		if !strings.HasSuffix(target, "."+suffix) {
			continue
		}
		// 通配只吃一层：剩下的部分不能再有点。
		if label := strings.TrimSuffix(target, "."+suffix); label != "" && !strings.Contains(label, ".") {
			return r.Value, true
		}
	}
	return "", false
}

// subDomainOf 把 FQDN 转成 DNSPod 的 sub_domain（根域用 @）。
func subDomainOf(fqdn, zone string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if name == zone {
		return "@"
	}
	if strings.HasSuffix(name, "."+zone) {
		return strings.TrimSuffix(name, "."+zone)
	}
	// 兜底：取 zone 前面那一截
	if i := strings.Index(name, "."); i > 0 {
		return name[:i]
	}
	return name
}

// normalizeApex 去掉通配符前缀与结尾的点：*.666086.xyz -> 666086.xyz
func normalizeApex(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "*.")
	return strings.TrimSuffix(d, ".")
}
