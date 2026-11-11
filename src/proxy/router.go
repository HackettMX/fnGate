package proxy

import (
	"strings"

	"fngate/core"
)

// pickRoute 在同一入口内按「域名精确度 + 路径长度」打分选最佳路由。
func pickRoute(routes []core.Route, host, path string) (core.Route, bool) {
	host = NormalizeDomain(host)
	var best core.Route
	bestScore := -1
	found := false
	for _, r := range routes {
		if !r.Enabled || !domainMatches(r.Domains, host) {
			continue
		}
		pfx := NormalizePathPrefix(r.PathPrefix)
		if !PathMatches(path, pfx, r.MatchType) {
			continue
		}
		score := 0
		if len(r.Domains) > 0 {
			// 精确域名优先于泛域名，泛域名优先于「任意域名」
			if containsExact(r.Domains, host) {
				score += 2000
			} else if containsWildcard(r.Domains) {
				score += 1000
			} else {
				score += 500
			}
		}
		if pfx != "" {
			score += len(pfx) * 2
		}
		if r.MatchType == "exact" {
			score += 1
		}
		if score > bestScore {
			bestScore = score
			best = r
			found = true
		}
	}
	return best, found
}

func domainMatches(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if MatchDomain(p, host) {
			return true
		}
	}
	return false
}

func containsExact(patterns []string, host string) bool {
	for _, p := range patterns {
		if NormalizeDomain(p) == host {
			return true
		}
	}
	return false
}

func containsWildcard(patterns []string) bool {
	for _, p := range patterns {
		if strings.HasPrefix(NormalizeDomain(p), "*.") {
			return true
		}
	}
	return false
}

// pickTCPRoute：TLS 按 SNI 匹配；非 TLS 或单规则端口走兜底，
// 否则 RDP/SSH 这类不带 SNI 的协议会被静默关掉。
func pickTCPRoute(routes []core.Route, sni string) (core.Route, bool) {
	sni = NormalizeDomain(sni)
	if sni != "" {
		var best core.Route
		bestScore := -1
		found := false
		for _, r := range routes {
			if !r.Enabled || !domainMatches(r.Domains, sni) {
				continue
			}
			score := 0
			if containsExact(r.Domains, sni) {
				score = 2
			} else if containsWildcard(r.Domains) {
				score = 1
			}
			if score > bestScore {
				bestScore, best, found = score, r, true
			}
		}
		if found {
			return best, true
		}
	}
	var anyDomain core.Route
	anyFound := false
	var only core.Route
	count := 0
	for _, r := range routes {
		if !r.Enabled {
			continue
		}
		only = r
		count++
		if len(r.Domains) == 0 && !anyFound {
			anyDomain, anyFound = r, true
		}
	}
	if anyFound {
		return anyDomain, true
	}
	if count == 1 {
		return only, true
	}
	return core.Route{}, false
}
