package acme

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// challengeTarget 描述一次 DNS-01 挑战最终的记录名。
//
// Query 是 CA 真正会去查的名字（_acme-challenge.<domain>），Target 是按 CNAME 链
// 走到底的名字。两者不同时，TXT **必须**写到 Target 上：按 RFC 1034，一个名字一旦
// 存在 CNAME，同名其他类型的记录都会被解析器忽略，CA 只会看到 CNAME 指向的那一侧。
type challengeTarget struct {
	Query  string   `json:"query"`
	Target string   `json:"target"`
	Chain  []string `json:"chain,omitempty"`
	Loop   bool     `json:"loop,omitempty"`
}

// Followed 表示该挑战需要沿 CNAME 写到别的名字上。
func (t challengeTarget) Followed() bool { return t.Target != "" && t.Target != t.Query }

// Describe 生成一行可读说明，用于订单日志。
func (t challengeTarget) Describe() string {
	if len(t.Chain) >= 2 {
		return strings.Join(t.Chain, " → ")
	}
	if t.Followed() {
		return t.Query + " → " + t.Target
	}
	return t.Query
}

// resolveChallengeName 计算挑战记录名，并自己跟随 CNAME。
//
// 不直接用 lego 的 ChallengeInfo.EffectiveFQDN：lego 跟随 CNAME 时只查
// recursiveNameservers 列表里的服务器，遇到本地 DNS 劫持/精简（NAS 上很常见）
// 就会跟丢，于是 TXT 被写到带 CNAME 的名字上，CA 永远读不到值，
// 最终报「TXT 记录值不正确」。
func resolveChallengeName(domain string, resolvers []string) challengeTarget {
	apex := normalizeApex(domain)
	if apex == "" {
		return challengeTarget{}
	}
	query := "_acme-challenge." + apex
	self := challengeTarget{Query: query, Target: query}
	if len(resolvers) == 0 {
		return self
	}

	cur := query
	seen := map[string]bool{dns.Fqdn(cur): true}
	for hop := 0; hop < 8; hop++ {
		next := lookupCNAMETarget(resolvers, cur)
		if next == "" {
			break
		}
		next = strings.ToLower(strings.TrimSuffix(next, "."))
		if next == "" || seen[dns.Fqdn(next)] {
			self.Loop = true
			return self
		}
		seen[dns.Fqdn(next)] = true
		self.Chain = append(self.Chain, cur)
		cur = next
	}
	self.Chain = append(self.Chain, cur)
	self.Target = cur
	return self
}

// lookupCNAMETarget 依次询问多台 DNS，返回第一台给出的 CNAME 目标。
//
// 必须逐台试：只要有一台返回「NOERROR 但没有 CNAME」就停，会把被劫持的那台
// 当成权威结论，正是这次故障的成因。
func lookupCNAMETarget(resolvers []string, name string) string {
	fq := dns.Fqdn(name)
	for _, srv := range resolvers {
		resp, err := dnsExchange(srv, name, dns.TypeCNAME)
		if err != nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range resp.Answer {
			cname, ok := rr.(*dns.CNAME)
			if !ok || !strings.EqualFold(cname.Hdr.Name, fq) {
				continue
			}
			return cname.Target
		}
	}
	return ""
}

// txtVisible 判断「CA 视角」下能否在 query 上读到 value。
//
// 直接查 query 本身，让解析器自己去跟随 CNAME——和 CA 的验证路径完全一致，
// 而不是去查我们以为的目标名。
func txtVisible(resolvers []string, query, value string) (bool, string) {
	if len(resolvers) == 0 {
		return false, "没有可用的 DNS 服务器"
	}
	var lastErr string
	for _, srv := range resolvers {
		resp, err := dnsExchange(srv, query, dns.TypeTXT)
		if err != nil {
			lastErr = fmt.Sprintf("%s 请求失败：%v", srv, err)
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Sprintf("%s 返回 %s", srv, dns.RcodeToString[resp.Rcode])
			continue
		}
		seenTXT := make([]string, 0, len(resp.Answer))
		for _, rr := range resp.Answer {
			txt, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}
			joined := strings.Join(txt.Txt, "")
			seenTXT = append(seenTXT, joined)
			if joined == value {
				return true, srv
			}
		}
		if len(seenTXT) == 0 {
			lastErr = fmt.Sprintf("%s 没有返回任何 TXT", srv)
			continue
		}
		lastErr = fmt.Sprintf("%s 返回的 TXT 与预期不一致", srv)
	}
	if lastErr == "" {
		lastErr = "没有可用的 DNS 服务器"
	}
	return false, lastErr
}

// waitTXTVisible 在限定时间内轮询，返回是否可见以及最后一次失败原因。
func waitTXTVisible(resolvers []string, query, value string, timeout time.Duration) (bool, string) {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		if ok, detail := txtVisible(resolvers, query, value); ok {
			return true, detail
		} else {
			last = detail
		}
		if !time.Now().Before(deadline) {
			return false, last
		}
		time.Sleep(3 * time.Second)
	}
}

// looksLikeACMEValue 判断一个 TXT 值是否像 ACME 的 key authorization：
// base64url(sha256(keyAuth)) 固定 43 个字符。用来识别历史残留，
// 避免误删用户在别处添加的普通 TXT。
func looksLikeACMEValue(v string) bool {
	v = strings.Trim(strings.TrimSpace(v), `"`)
	if len(v) != 43 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
