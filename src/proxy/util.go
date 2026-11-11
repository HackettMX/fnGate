package proxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Backend struct {
	Scheme   string
	Host     string
	BasePath string
}

// ParseBackend 保留用户显式写的 scheme，避免把 https 后端降级成 http。
func ParseBackend(raw, defaultScheme string) (Backend, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Backend{}, fmt.Errorf("后端地址不能为空")
	}
	if !strings.Contains(s, "://") {
		s = defaultScheme + "://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Backend{}, fmt.Errorf("后端地址无法解析: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Backend{}, fmt.Errorf("后端仅支持 http/https，当前为 %q", u.Scheme)
	}
	if u.Host == "" {
		return Backend{}, fmt.Errorf("后端地址缺少主机名，例如 192.168.1.50:8096")
	}
	return Backend{Scheme: u.Scheme, Host: u.Host, BasePath: strings.TrimSuffix(u.Path, "/")}, nil
}

func (b Backend) HostPort() string {
	if _, _, err := net.SplitHostPort(b.Host); err == nil {
		return b.Host
	}
	port := "80"
	if b.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(b.Host, port)
}

func (b Backend) URL() string {
	return (&url.URL{Scheme: b.Scheme, Host: b.Host, Path: b.BasePath}).String()
}

func NormalizeHostPort(raw string) string {
	scheme := "http"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "https://") {
		scheme = "https"
	}
	bd, err := ParseBackend(raw, scheme)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return bd.HostPort()
}

func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// NormalizeDomain 去掉 scheme / 路径 / 端口，统一小写。
func NormalizeDomain(s string) string {
	v := strings.TrimSpace(s)
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
}

func NormalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if d := NormalizeDomain(s); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// MatchDomain 支持精确域名、*.example.com 泛域名与空（任意）。
// 泛域名只匹配一级子域：*.example.com 命中 a.example.com，不命中 a.b.example.com。
func MatchDomain(pattern, host string) bool {
	pattern = NormalizeDomain(pattern)
	host = NormalizeDomain(host)
	if pattern == "" {
		return true
	}
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	base := strings.TrimPrefix(pattern, "*.")
	if host == base || !strings.HasSuffix(host, "."+base) {
		return false
	}
	rest := strings.TrimSuffix(host, "."+base)
	return rest != "" && !strings.Contains(rest, ".")
}

func NormalizePathPrefix(s string) string {
	v := strings.TrimSpace(s)
	if v == "" || v == "/" {
		return ""
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return strings.TrimRight(v, "/")
}

func PathMatches(path, prefix, matchType string) bool {
	p := NormalizePathPrefix(prefix)
	if p == "" {
		return true
	}
	path = strings.ToLower(path)
	p = strings.ToLower(p)
	if matchType == "exact" {
		return path == p || path == p+"/"
	}
	if !strings.HasPrefix(path, p) {
		return false
	}
	rest := path[len(p):]
	return rest == "" || strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "?")
}

func StripHostPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func listenAddr(bind string, port int) string {
	if strings.TrimSpace(bind) == "" {
		bind = "0.0.0.0"
	}
	return net.JoinHostPort(bind, strconv.Itoa(port))
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if a == "" {
			return b
		}
		return a + "/" + b
	}
	if a == "" {
		return b
	}
	return a + b
}
