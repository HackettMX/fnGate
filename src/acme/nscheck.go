package acme

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// 传播校验相关的 DNS 探测。
//
// 背景：lego 的传播检查要求先列出 zone apex 的权威 NS（查询 NS 记录），
// 只要 Answer 段为空就判定失败。但部分 DNS 服务商（如 DNSPod 免费版）
// 对 apex 的 NS 查询只返回 authority 段的 SOA，不返回 NS：
//
//	;; QUESTION: 666086.xyz. IN NS
//	;; AUTHORITY: 666086.xyz. 180 IN SOA f1g1ns1.dnspod.net. ...
//	;; ANSWER:   (空)
//
// 于是签发在等待 2 分钟后抛 "could not determine authoritative nameservers"，
// 而 TXT 记录其实早已写对。这里补一层探测：NS 拿不到时回退 SOA 的 MNAME，
// 再不行才判定域名委派有问题，并让上层切换成「递归解析校验」。

const (
	dnsCheckAuto      = "auto"
	dnsCheckStrict    = "strict"
	dnsCheckRecursive = "recursive"
)

// 探测用的兜底 DNS：优先系统配置；系统 DNS 失效时仍能给出结论。
var fallbackResolvers = []string{"223.5.5.5:53", "119.29.29.29:53"}

var (
	resolverCacheMu sync.Mutex
	resolverCache   []string
	resolverCachAt  time.Time
)

// systemResolvers 读取 /etc/resolv.conf 里的 nameserver 列表（带 1 分钟缓存）。
func systemResolvers() []string {
	resolverCacheMu.Lock()
	defer resolverCacheMu.Unlock()
	if len(resolverCache) > 0 && time.Since(resolverCachAt) < time.Minute {
		return append([]string(nil), resolverCache...)
	}
	var out []string
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "nameserver" {
				out = append(out, net.JoinHostPort(fields[1], "53"))
			}
		}
	}
	resolverCache, resolverCachAt = out, time.Now()
	return append([]string(nil), out...)
}

// normalizeResolvers 补全端口并去重。
func normalizeResolvers(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, "53")
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// effectiveResolvers 决定本次探测使用哪些 DNS 服务器。
//
// 与 lego 默认行为（只用 /etc/resolv.conf，失败后落到 Google DNS）不同：
// 国内 NAS 上 8.8.8.8 常常不可达，这里改成「系统 DNS + 国内公共 DNS」合并，
// 只要有一台能给出答案就算通过。
func effectiveResolvers(custom []string) []string {
	if len(custom) > 0 {
		return normalizeResolvers(custom)
	}
	all := append([]string(nil), systemResolvers()...)
	all = append(all, fallbackResolvers...)
	return normalizeResolvers(all)
}

func dnsExchange(server, name string, qtype uint16) (*dns.Msg, error) {
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		c.Net = "tcp"
		if tcpResp, _, tcpErr := c.Exchange(m, server); tcpErr == nil {
			return tcpResp, nil
		}
	}
	return resp, nil
}

// FirstResolverAnswer 依次向多台 DNS 发起查询，返回第一个 rcode=NOERROR 的响应。
// 用于「至少有一台能看到」这类判定，避免单台 DNS 故障导致误判。
func firstResolverAnswer(resolvers []string, name string, qtype uint16) (*dns.Msg, string, error) {
	var lastErr error
	for _, r := range resolvers {
		resp, err := dnsExchange(r, name, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s 返回 %s", r, dns.RcodeToString[resp.Rcode])
			continue
		}
		return resp, r, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用的 DNS 服务器")
	}
	return nil, "", lastErr
}

// findZone 由 FQDN 逐级向上查找 SOA，得到它所属的 zone apex。
func findZone(fqdn string, resolvers []string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		resp, _, err := firstResolverAnswer(resolvers, candidate, dns.TypeSOA)
		if err != nil {
			continue
		}
		for _, rr := range resp.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				return strings.TrimSuffix(strings.ToLower(soa.Hdr.Name), "."), nil
			}
		}
	}
	return "", fmt.Errorf("无法确定 %s 所属的 DNS 区域（SOA 查询失败）", fqdn)
}

// apexNameservers 返回 zone 的权威 NS。
// source 为 "NS" 表示直接列出；"SOA" 表示回退到 SOA 的 MNAME（DNSPod 免费版属于这种）。
func apexNameservers(zone string, resolvers []string) (ns []string, source string, err error) {
	resp, _, qerr := firstResolverAnswer(resolvers, zone, dns.TypeNS)
	if qerr == nil {
		for _, rr := range resp.Answer {
			if rec, ok := rr.(*dns.NS); ok {
				ns = append(ns, strings.TrimSuffix(strings.ToLower(rec.Ns), "."))
			}
		}
		if len(ns) > 0 {
			return dedupeStrings(ns), "NS", nil
		}
	}
	// 回退：SOA 的 MNAME 就是该 zone 的主权威服务器。
	soaResp, _, soaErr := firstResolverAnswer(resolvers, zone, dns.TypeSOA)
	if soaErr != nil {
		if qerr != nil {
			return nil, "", qerr
		}
		return nil, "", soaErr
	}
	collect := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if soa, ok := rr.(*dns.SOA); ok && soa.Ns != "" {
				ns = append(ns, strings.TrimSuffix(strings.ToLower(soa.Ns), "."))
			}
		}
	}
	collect(soaResp.Answer)
	collect(soaResp.Ns)
	ns = dedupeStrings(ns)
	if len(ns) == 0 {
		return nil, "", fmt.Errorf("zone %s 既查不到 NS 记录，也查不到 SOA", zone)
	}
	return ns, "SOA", nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// lookupTXT 查询某名字的 TXT 记录值（跟随 CNAME 由 DNS 服务器完成）。
func lookupTXT(fqdn string, resolvers []string) (values []string, cname string, err error) {
	resp, _, err := firstResolverAnswer(resolvers, fqdn, dns.TypeTXT)
	if err != nil {
		return nil, "", err
	}
	for _, rr := range resp.Answer {
		switch rec := rr.(type) {
		case *dns.CNAME:
			if cname == "" {
				cname = strings.TrimSuffix(rec.Target, ".")
			}
		case *dns.TXT:
			values = append(values, strings.Join(rec.Txt, ""))
		}
	}
	return values, cname, nil
}

// describeCheckPlan 把校验策略转成一行人类可读的说明，写入订单日志。
func describeCheckPlan(p dnsCheckPlan) string {
	head := "传播校验：权威 NS"
	if p.Mode == dnsCheckRecursive {
		head = "传播校验：递归解析"
	}
	parts := []string{head}
	if p.Zone != "" {
		detail := "区域 " + p.Zone
		if len(p.NS) > 0 {
			src := "NS"
			if p.NSource == "SOA" {
				src = "SOA"
			}
			detail += fmt.Sprintf("，权威 NS（来自 %s）：%s", src, strings.Join(p.NS, "、"))
		}
		parts = append(parts, detail)
	}
	if p.Reason != "" {
		parts = append(parts, p.Reason)
	}
	return strings.Join(parts, "；")
}

// dnsCheckPlan 描述本次签发该如何做传播校验。
type dnsCheckPlan struct {
	Mode      string // strict | recursive
	Zone      string
	NS        []string
	NSource   string // NS | SOA
	Resolvers []string
	Reason    string
}

// planDNSCheck 根据设置与域名实际情况决定校验方式。
//
// 返回 error 表示域名委派本身有问题（连 SOA 都查不到），此时应在提交 CA 之前就失败，
// 而不是让用户等两分钟看一句超时。
func planDNSCheck(domains []string, mode string, customResolvers []string) (dnsCheckPlan, error) {
	resolvers := effectiveResolvers(customResolvers)
	plan := dnsCheckPlan{Mode: dnsCheckStrict, Resolvers: resolvers}

	base := ""
	for _, d := range domains {
		d = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "*."))
		if d != "" {
			base = d
			break
		}
	}
	if base == "" {
		return plan, fmt.Errorf("订单没有有效域名")
	}

	zone, err := findZone(base, resolvers)
	if err != nil {
		return plan, err
	}
	plan.Zone = zone

	ns, source, nsErr := apexNameservers(zone, resolvers)
	if nsErr == nil {
		plan.NS, plan.NSource = ns, source
	}

	switch mode {
	case dnsCheckRecursive:
		plan.Mode = dnsCheckRecursive
		plan.Reason = "已按设置使用「递归解析校验」"
	case dnsCheckStrict:
		plan.Mode = dnsCheckStrict
		if nsErr != nil {
			return plan, fmt.Errorf("无法获取 %s 的权威 NS：%w；请确认域名的 NS 已指向当前 DNS 服务商", zone, nsErr)
		}
		if source == "SOA" {
			return plan, fmt.Errorf("%s 的 NS 查询返回空答案，无法做严格校验", zone)
		}
	default: // auto
		if nsErr != nil {
			plan.Mode = dnsCheckRecursive
			plan.Reason = "无法获取 zone apex 的 NS 记录，已自动改用递归解析校验"
			break
		}
		if source == "SOA" {
			// NS 查询返回空、只能靠 SOA 拿到主 NS，说明这套 DNS 不按 RFC 返回 apex NS。
			// lego 的严格检查必然失败，直接走递归校验，省掉两分钟的空等。
			plan.Mode = dnsCheckRecursive
			plan.Reason = fmt.Sprintf("该 DNS 对 %s 的 NS 查询返回空答案（常见于 DNSPod），已自动改用递归解析校验", zone)
			break
		}
		plan.Reason = "权威 NS 正常，使用严格校验"
	}
	return plan, nil
}
