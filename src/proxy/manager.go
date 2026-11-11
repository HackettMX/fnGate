package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fngate/core"
)

type ListenerState struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Active   bool   `json:"active"`
	Error    string `json:"error,omitempty"`
	Routes   int    `json:"routes"`
	CertID   string `json:"cert_id,omitempty"`
}

type StatusView struct {
	Listeners   []ListenerState `json:"listeners"`
	Routes      int             `json:"routes"`
	Failed      int             `json:"failed"`
	Healthy     int             `json:"healthy"`
	RunUser     string          `json:"run_user"`
	CanBindLow  bool            `json:"can_bind_low"`
	AccessLines int             `json:"access_lines"`
}

// runtimeView 每次配置变更整体替换：handler 每请求读取，
// 因此只改路由时不会重建任何 TCP 监听，已建立的连接不受影响。
type runtimeView struct {
	listeners map[string]core.Listener
	routes    map[string][]core.Route
}

type listenerRuntime struct {
	spec  string
	ln    net.Listener
	srv   *http.Server
	conns *connSet
}

type Manager struct {
	store *core.Store
	bus   *core.EventBus
	log   *core.Logger

	resolverMu sync.RWMutex
	resolver   CertResolver

	view          atomic.Value
	mu            sync.RWMutex
	runtimes      map[string]*listenerRuntime
	states        []ListenerState
	proxyCache    sync.Map
	accessLines   []string
	accessMu      sync.Mutex
	accessEnabled atomic.Bool

	health       map[string]bool
	healthMu     sync.RWMutex
	lastHealth   time.Time
	healthTickMu sync.Mutex
}

func New(store *core.Store, bus *core.EventBus, log *core.Logger, sched *core.Scheduler, certsDir string) *Manager {
	m := &Manager{
		store: store, bus: bus, log: log,
		runtimes: map[string]*listenerRuntime{},
		states:   []ListenerState{},
		health:   map[string]bool{},
	}
	m.SetCertResolver(NewSelfSignedResolver(certsDir))
	m.view.Store(&runtimeView{listeners: map[string]core.Listener{}, routes: map[string][]core.Route{}})
	sched.Every("proxy.health", 5*time.Second, m.healthTick)
	return m
}

func (m *Manager) SetCertResolver(r CertResolver) {
	if r == nil {
		return
	}
	m.resolverMu.Lock()
	m.resolver = r
	m.resolverMu.Unlock()
}

func (m *Manager) certResolver() CertResolver {
	m.resolverMu.RLock()
	defer m.resolverMu.RUnlock()
	return m.resolver
}

func specOf(l core.Listener) string {
	b, _ := json.Marshal(l)
	return string(b)
}

// Apply 把当前配置应用到运行时，只重建「新增 / 配置变化 / 删除」的入口。
func (m *Manager) Apply() []ListenerState {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.store.Snapshot()
	m.accessEnabled.Store(st.Settings.AccessLog)
	view := &runtimeView{
		listeners: map[string]core.Listener{},
		routes:    map[string][]core.Route{},
	}
	for _, l := range st.Listeners {
		if l.Enabled {
			view.listeners[l.ID] = l
		}
	}
	for _, r := range st.Routes {
		if !r.Enabled {
			continue
		}
		if _, ok := view.listeners[r.ListenerID]; ok {
			view.routes[r.ListenerID] = append(view.routes[r.ListenerID], r)
		}
	}
	m.view.Store(view)

	signatures := map[string]bool{}
	for _, list := range view.routes {
		for _, r := range list {
			signatures[routeSignature(r)] = true
		}
	}
	m.pruneCache(signatures)

	desired := map[string]string{}
	for id, l := range view.listeners {
		desired[id] = specOf(l)
	}
	for id, rt := range m.runtimes {
		if spec, ok := desired[id]; !ok || spec != rt.spec {
			m.stopRuntimeLocked(rt)
			delete(m.runtimes, id)
		}
	}

	states := make([]ListenerState, 0, len(st.Listeners))
	for id, l := range view.listeners {
		if _, running := m.runtimes[id]; !running {
			rt, err := m.startListener(l)
			if err != nil {
				states = append(states, ListenerState{
					ID: id, Name: l.Name, Port: l.Port, Protocol: l.Protocol,
					Active: false, Error: err.Error(), Routes: len(view.routes[id]), CertID: l.TLS.CertID,
				})
				m.bus.Publish("proxy", "error", "入口「%s」端口 %d 启动失败：%s", l.Name, l.Port, err.Error())
				continue
			}
			m.runtimes[id] = rt
			m.bus.Publish("proxy", "info", "入口「%s」已在端口 %d 启动（%s）", l.Name, l.Port, strings.ToUpper(l.Protocol))
		}
		states = append(states, ListenerState{
			ID: id, Name: l.Name, Port: l.Port, Protocol: l.Protocol,
			Active: true, Routes: len(view.routes[id]), CertID: l.TLS.CertID,
		})
	}
	for _, l := range st.Listeners {
		if !l.Enabled {
			states = append(states, ListenerState{
				ID: l.ID, Name: l.Name, Port: l.Port, Protocol: l.Protocol,
				Active: false, Error: "入口已停用",
			})
		}
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Port < states[j].Port })
	m.states = states
	return states
}

func (m *Manager) startListener(l core.Listener) (*listenerRuntime, error) {
	ln, err := net.Listen("tcp", listenAddr(l.Bind, l.Port))
	if err != nil {
		return nil, fmt.Errorf("端口 %d 无法监听：%s", l.Port, humanizeBindErr(err))
	}
	rt := &listenerRuntime{spec: specOf(l), ln: ln, conns: newConnSet()}
	switch l.Protocol {
	case "http", "https":
		srv := &http.Server{Handler: m.buildHTTPHandler(l.ID, l.Protocol), ReadHeaderTimeout: 10 * time.Second}
		var serveLn net.Listener = ln
		if l.Protocol == "https" {
			serveLn = tls.NewListener(ln, m.tlsConfig(l))
		}
		rt.srv = srv
		go func(port int, s *http.Server, sl net.Listener) {
			if e := s.Serve(sl); e != nil && e != http.ErrServerClosed {
				m.log.Warn("入口 %d 退出: %v", port, e)
			}
		}(l.Port, srv, serveLn)
	case "tcp":
		go m.acceptTCP(l.ID, ln, rt.conns)
	default:
		_ = ln.Close()
		return nil, fmt.Errorf("不支持的协议 %q（仅 http / https / tcp）", l.Protocol)
	}
	return rt, nil
}

func (m *Manager) stopRuntimeLocked(rt *listenerRuntime) {
	if rt.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = rt.srv.Shutdown(ctx)
		cancel()
		_ = rt.srv.Close()
	}
	_ = rt.ln.Close()
	rt.conns.CloseAll()
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, rt := range m.runtimes {
		m.stopRuntimeLocked(rt)
		delete(m.runtimes, id)
	}
}

func (m *Manager) healthTick() {
	st := m.store.Snapshot()
	interval := time.Duration(st.Settings.HealthInterval) * time.Second
	m.healthTickMu.Lock()
	if time.Since(m.lastHealth) < interval {
		m.healthTickMu.Unlock()
		return
	}
	m.lastHealth = time.Now()
	m.healthTickMu.Unlock()

	backends := map[string]bool{}
	for _, r := range st.Routes {
		if r.Enabled {
			backends[NormalizeHostPort(r.Backend)] = true
		}
	}
	type result struct {
		addr string
		up   bool
	}
	ch := make(chan result, len(backends))
	var wg sync.WaitGroup
	for addr := range backends {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", a, 2*time.Second)
			if c != nil {
				_ = c.Close()
			}
			ch <- result{addr: a, up: err == nil}
		}(addr)
	}
	wg.Wait()
	close(ch)
	m.healthMu.Lock()
	for x := range ch {
		m.health[x.addr] = x.up
	}
	m.healthMu.Unlock()
}

func (m *Manager) Health(addr string) (bool, bool) {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()
	v, ok := m.health[addr]
	return v, ok
}

func (m *Manager) Status() StatusView {
	m.mu.RLock()
	states := append([]ListenerState(nil), m.states...)
	m.mu.RUnlock()
	st := m.store.Snapshot()
	healthy := 0
	m.healthMu.RLock()
	for _, v := range m.health {
		if v {
			healthy++
		}
	}
	m.healthMu.RUnlock()
	failed := 0
	for _, s := range states {
		if !s.Active && s.Error != "" && !strings.Contains(s.Error, "停用") {
			failed++
		}
	}
	return StatusView{
		Listeners: states, Routes: len(st.Routes), Failed: failed, Healthy: healthy,
		RunUser: core.RuntimeUser(), CanBindLow: core.CanBindLowPort(),
		AccessLines: len(m.AccessLogs(0)),
	}
}

func (m *Manager) Summarize() map[string]interface{} {
	s := m.Status()
	return map[string]interface{}{
		"listeners": s.Listeners,
		"routes":    s.Routes,
		"failed":    s.Failed,
		"healthy":   s.Healthy,
	}
}

func humanizeBindErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "address already in use"), strings.Contains(s, "Only one usage of each socket address"):
		return "端口已被其他程序占用（也可能是飞牛系统自身的服务）"
	case strings.Contains(s, "permission denied"), strings.Contains(s, "access denied"):
		return "没有权限绑定该端口：1024 以下端口需要 cap_net_bind_service，请重启应用或改用 1024 以上端口"
	case strings.Contains(s, "invalid port"), strings.Contains(s, "out of range"):
		return "端口号超出合法范围"
	case strings.Contains(s, "cannot assign requested address"):
		return "该监听地址不可用"
	}
	return s
}
