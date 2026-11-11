package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// Secure 实现 D8：同源校验 + 写操作 CSRF Token。
// 管理面走统一网关（复用系统登录态），但 disable_authorization_path=true 时
// 应用自身必须挡住跨站写请求。
type Secure struct {
	token string
}

func newSecure() *Secure {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return &Secure{token: "fngate-fallback-token"}
	}
	return &Secure{token: hex.EncodeToString(b)}
}

func (s *Secure) Token() string { return s.token }

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func sameOrigin(r *http.Request) bool {
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" {
		return site == "same-origin" || site == "same-site" || site == "none"
	}
	expected := strings.ToLower(r.Host)
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return hostOf(origin) == expected
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref != "" {
		return hostOf(ref) == expected
	}
	// 网关转发可能不带来源头，此时由 CSRF Token 独立把关。
	return true
}

func (s *Secure) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, "请求来源与本机不一致，已拒绝")
			return
		}
		got := r.Header.Get("X-CSRF-Token")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeErr(w, http.StatusForbidden, "CSRF 校验失败，请刷新页面后重试")
			return
		}
		next.ServeHTTP(w, r)
	})
}
