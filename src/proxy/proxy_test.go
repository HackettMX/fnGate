package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"fngate/core"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	bus := core.NewEventBus()
	log, err := core.NewLogger(dir, "ERROR")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	st, err := core.NewStore(filepath.Join(dir, "state.json"), filepath.Join(dir, "secrets"), bus)
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, bus, log, core.NewScheduler(), filepath.Join(dir, "certs"))
	t.Cleanup(func() { m.Close() })
	return m
}

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"", "anything.example.com", true},
		{"a.example.com", "A.Example.COM", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"a.example.com", "b.example.com", false},
	}
	for _, c := range cases {
		if got := MatchDomain(c.pattern, c.host); got != c.want {
			t.Errorf("MatchDomain(%q,%q)=%v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestPathMatches(t *testing.T) {
	if !PathMatches("/emby/web", "/emby", "prefix") {
		t.Fatal("前缀应命中子路径")
	}
	if PathMatches("/embyx", "/emby", "prefix") {
		t.Fatal("路径段边界不应被跨越")
	}
	if !PathMatches("/api/", "/api", "exact") {
		t.Fatal("exact 应允许尾斜杠")
	}
	if PathMatches("/api/v1", "/api", "exact") {
		t.Fatal("exact 不应命中子路径")
	}
}

func TestParseBackendKeepsHTTPS(t *testing.T) {
	bd, err := ParseBackend("https://10.0.0.2:8443", "http")
	if err != nil {
		t.Fatal(err)
	}
	if bd.Scheme != "https" || bd.Host != "10.0.0.2:8443" {
		t.Fatalf("https 后端被错误改写: %+v", bd)
	}
	if got := bd.HostPort(); got != "10.0.0.2:8443" {
		t.Fatalf("HostPort=%s", got)
	}
}

func TestPickRoutePriority(t *testing.T) {
	routes := []core.Route{
		{ID: "any", Domains: nil, PathPrefix: "", Enabled: true},
		{ID: "wild", Domains: []string{"*.example.com"}, PathPrefix: "", Enabled: true},
		{ID: "exact", Domains: []string{"a.example.com"}, PathPrefix: "", Enabled: true},
		{ID: "long", Domains: []string{"a.example.com"}, PathPrefix: "/app", Enabled: true},
	}
	r, ok := pickRoute(routes, "a.example.com:443", "/app/index.html")
	if !ok || r.ID != "long" {
		t.Fatalf("应命中精确域名+最长路径，实际 %q", r.ID)
	}
	r, ok = pickRoute(routes, "b.example.com", "/")
	if !ok || r.ID != "wild" {
		t.Fatalf("应命中泛域名，实际 %q", r.ID)
	}
	r, ok = pickRoute(routes, "other.test", "/")
	if !ok || r.ID != "any" {
		t.Fatalf("应命中任意域名，实际 %q", r.ID)
	}
}

func TestPickTCPRouteSingleRuleFallback(t *testing.T) {
	routes := []core.Route{{ID: "rdp", Domains: []string{"rdp.example.com"}, Backend: "10.0.0.5:3389", Enabled: true}}
	if _, ok := pickTCPRoute(routes, ""); !ok {
		t.Fatal("单规则端口不应要求 SNI")
	}
	routes = append(routes, core.Route{ID: "ssh", Domains: []string{"ssh.example.com"}, Backend: "10.0.0.5:22", Enabled: true})
	if _, ok := pickTCPRoute(routes, ""); ok {
		t.Fatal("多规则端口且无任意域名规则时不应静默命中")
	}
	if r, ok := pickTCPRoute(routes, "ssh.example.com"); !ok || r.ID != "ssh" {
		t.Fatal("应按 SNI 命中对应规则")
	}
}

func TestPureRouteChangeKeepsListener(t *testing.T) {
	m := newTestManager(t)
	const lid = "listener-test"
	err := m.store.Update(func(s *core.State) error {
		s.Listeners = append(s.Listeners, core.Listener{
			ID: lid, Name: "test", Port: 0, Protocol: "http", Bind: "127.0.0.1", Enabled: true,
		})
		s.Routes = append(s.Routes, core.Route{
			ID: "r1", ListenerID: lid, Domains: []string{"a.example.com"},
			Backend: "127.0.0.1:9999", Enabled: true,
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	states := m.Apply()
	if len(states) != 1 || !states[0].Active {
		t.Fatalf("入口启动失败: %+v", states)
	}
	m.mu.RLock()
	first := m.runtimes[lid]
	m.mu.RUnlock()
	if first == nil {
		t.Fatal("运行时监听未建立")
	}
	if err := m.store.Update(func(s *core.State) error {
		s.Routes[0].Backend = "127.0.0.1:9998"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m.Apply()
	m.mu.RLock()
	second := m.runtimes[lid]
	m.mu.RUnlock()
	if first != second {
		t.Fatal("只修改路由不应重建监听（会断开已有连接）")
	}
}

func TestHTTPProxyEndToEnd(t *testing.T) {
	var seenPath, seenHeader, seenForwarded string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenHeader = r.Header.Get("X-Test-Header")
		seenForwarded = r.Header.Get("X-Forwarded-Host")
		w.Header().Set("X-Backend", "yes")
		_, _ = fmt.Fprintf(w, "OK:%s", r.URL.Path)
	}))
	defer backend.Close()
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t)
	const lid = "listener-e2e"
	err = m.store.Update(func(s *core.State) error {
		s.Listeners = append(s.Listeners, core.Listener{
			ID: lid, Name: "e2e", Port: 0, Protocol: "http", Bind: "127.0.0.1", Enabled: true,
		})
		s.Routes = append(s.Routes, core.Route{
			ID: "r-e2e", ListenerID: lid, Name: "e2e", PathPrefix: "/svc", MatchType: "prefix",
			Backend: u.Host, StripPrefix: true, Websocket: true, TimeoutMS: 5000,
			RequestHeaders: map[string]string{"X-Test-Header": "yes"}, Enabled: true,
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	states := m.Apply()
	if len(states) != 1 || !states[0].Active {
		t.Fatalf("入口启动失败: %+v", states)
	}
	m.mu.RLock()
	rt := m.runtimes[lid]
	m.mu.RUnlock()
	if rt == nil {
		t.Fatal("运行时监听未建立")
	}
	resp, err := http.Get("http://" + rt.ln.Addr().String() + "/svc/hello?x=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "OK:/hello" {
		t.Fatalf("转发结果异常: status=%d body=%q", resp.StatusCode, body)
	}
	if seenPath != "/hello" {
		t.Errorf("路径前缀未剥离，后端收到 %q", seenPath)
	}
	if seenHeader != "yes" {
		t.Errorf("请求头改写未生效: %q", seenHeader)
	}
	if seenForwarded == "" || resp.Header.Get("X-Backend") != "yes" {
		t.Error("转发头或响应头丢失")
	}
}
