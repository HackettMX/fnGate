package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fngate/api"
	"fngate/core"
)

type API struct {
	m     *Manager
	store *core.Store
}

func NewModule(m *Manager, store *core.Store) *API { return &API{m: m, store: store} }

func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", a.status)
	mux.HandleFunc("GET /overview", a.overview)
	mux.HandleFunc("GET /logs", a.logs)
	mux.HandleFunc("POST /apply", a.apply)
	mux.HandleFunc("POST /listeners", a.addListener)
	mux.HandleFunc("PUT /listeners/{id}", a.updateListener)
	mux.HandleFunc("DELETE /listeners/{id}", a.deleteListener)
	mux.HandleFunc("POST /routes", a.addRoute)
	mux.HandleFunc("PUT /routes/{id}", a.updateRoute)
	mux.HandleFunc("DELETE /routes/{id}", a.deleteRoute)
	return mux
}

func (a *API) Summarize() map[string]interface{} { return a.m.Summarize() }

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func nowText() string { return time.Now().Format("2006-01-02 15:04:05") }

type listenerPayload struct {
	Name     string         `json:"name"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Bind     string         `json:"bind"`
	Enabled  *bool          `json:"enabled"`
	TLS      core.TLSConfig `json:"tls"`
}

func (a *API) buildListener(p listenerPayload, existing *core.Listener) (core.Listener, error) {
	l := core.Listener{}
	if existing != nil {
		l = *existing
	}
	l.Name = strings.TrimSpace(p.Name)
	l.Port = p.Port
	l.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	l.Bind = strings.TrimSpace(p.Bind)
	l.TLS = p.TLS
	l.Enabled = true
	if p.Enabled != nil {
		l.Enabled = *p.Enabled
	}
	if existing != nil && p.Enabled == nil {
		l.Enabled = existing.Enabled
	}
	if !ValidPort(l.Port) {
		return l, fmt.Errorf("监听端口必须在 1-65535 之间")
	}
	switch l.Protocol {
	case "http", "https", "tcp":
	default:
		return l, fmt.Errorf("协议只能是 http / https / tcp")
	}
	if l.Bind == "" {
		l.Bind = "0.0.0.0"
	}
	if net.ParseIP(l.Bind) == nil {
		return l, fmt.Errorf("监听地址不是合法 IP：%s", l.Bind)
	}
	if l.Name == "" {
		l.Name = fmt.Sprintf("入口 %d", l.Port)
	}
	if l.TLS.MinVersion == "" {
		l.TLS.MinVersion = "1.2"
	}
	if l.TLS.MinVersion != "1.2" && l.TLS.MinVersion != "1.3" {
		return l, fmt.Errorf("TLS 最低版本只能是 1.2 或 1.3")
	}
	if l.Protocol != "https" {
		l.TLS.HSTS = false
		l.TLS.CertID = ""
	}
	if l.Protocol == "tcp" {
		l.TLS = core.TLSConfig{MinVersion: "1.2"}
	}
	for _, other := range a.store.Snapshot().Listeners {
		if other.ID == l.ID || other.Port != l.Port {
			continue
		}
		return l, fmt.Errorf("端口 %d 已被入口「%s」占用，同一端口只能建立一个入口", l.Port, other.Name)
	}
	if l.ID == "" {
		l.ID = newID()
		l.CreatedAt = nowText()
	}
	return l, nil
}

type routePayload struct {
	ListenerID       string            `json:"listener_id"`
	Name             string            `json:"name"`
	Domains          []string          `json:"domains"`
	PathPrefix       string            `json:"path_prefix"`
	MatchType        string            `json:"match_type"`
	Backend          string            `json:"backend"`
	StripPrefix      *bool             `json:"strip_prefix"`
	VerifyBackendTLS *bool             `json:"verify_backend_tls"`
	Websocket        *bool             `json:"websocket"`
	TimeoutMS        int               `json:"timeout_ms"`
	RequestHeaders   map[string]string `json:"request_headers"`
	CertID           string            `json:"cert_id"`
	Enabled          *bool             `json:"enabled"`
	Description      string            `json:"description"`
}

func (a *API) buildRoute(p routePayload, existing *core.Route) (core.Route, error) {
	r := core.Route{}
	if existing != nil {
		r = *existing
	}
	r.ListenerID = strings.TrimSpace(p.ListenerID)
	r.Name = strings.TrimSpace(p.Name)
	r.Domains = NormalizeDomains(p.Domains)
	r.PathPrefix = NormalizePathPrefix(p.PathPrefix)
	r.MatchType = strings.ToLower(strings.TrimSpace(p.MatchType))
	r.Backend = strings.TrimSpace(p.Backend)
	r.RequestHeaders = p.RequestHeaders
	r.CertID = strings.TrimSpace(p.CertID)
	r.Description = strings.TrimSpace(p.Description)
	r.TimeoutMS = p.TimeoutMS
	r.Enabled = true
	if p.Enabled != nil {
		r.Enabled = *p.Enabled
	}
	if existing != nil && p.Enabled == nil {
		r.Enabled = existing.Enabled
	}
	r.StripPrefix = true
	if p.StripPrefix != nil {
		r.StripPrefix = *p.StripPrefix
	}
	if existing != nil && p.StripPrefix == nil {
		r.StripPrefix = existing.StripPrefix
	}
	r.Websocket = true
	if p.Websocket != nil {
		r.Websocket = *p.Websocket
	}
	if existing != nil && p.Websocket == nil {
		r.Websocket = existing.Websocket
	}
	r.VerifyBackendTLS = false
	if p.VerifyBackendTLS != nil {
		r.VerifyBackendTLS = *p.VerifyBackendTLS
	}
	if existing != nil && p.VerifyBackendTLS == nil {
		r.VerifyBackendTLS = existing.VerifyBackendTLS
	}

	st := a.store.Snapshot()
	var listener *core.Listener
	for i := range st.Listeners {
		if st.Listeners[i].ID == r.ListenerID {
			listener = &st.Listeners[i]
			break
		}
	}
	if listener == nil {
		return r, fmt.Errorf("入口不存在，请刷新页面后重试")
	}
	if r.MatchType == "" {
		r.MatchType = "prefix"
	}
	if r.MatchType != "prefix" && r.MatchType != "exact" {
		return r, fmt.Errorf("匹配方式只能是 prefix / exact")
	}
	if listener.Protocol == "tcp" {
		r.PathPrefix, r.StripPrefix, r.MatchType = "", false, "prefix"
	}
	if r.Backend == "" {
		return r, fmt.Errorf("后端地址不能为空")
	}
	if listener.Protocol != "tcp" {
		if _, err := ParseBackend(r.Backend, "http"); err != nil {
			return r, err
		}
	} else if _, _, err := net.SplitHostPort(NormalizeHostPort(r.Backend)); err != nil {
		return r, fmt.Errorf("TCP 路由的后端必须写明端口，例如 192.168.1.50:3389")
	}
	if r.TimeoutMS <= 0 {
		r.TimeoutMS = 30000
	}
	if r.TimeoutMS < 1000 || r.TimeoutMS > 600000 {
		return r, fmt.Errorf("超时需在 1000-600000 毫秒之间")
	}
	if r.Name == "" {
		r.Name = r.Backend
	}
	for k := range r.RequestHeaders {
		if strings.TrimSpace(k) == "" || strings.ContainsAny(k, "\r\n:") {
			return r, fmt.Errorf("请求头名称不合法")
		}
	}
	if listener.Protocol != "https" {
		// 只有 HTTPS 入口终止 TLS；HTTP/TCP 入口挂证书没有意义，也不该让用户误以为已启用 HTTPS。
		r.CertID = ""
	}
	if r.ID == "" {
		r.ID = newID()
		r.CreatedAt = nowText()
	}
	return r, nil
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, a.m.Status())
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	st := a.store.Snapshot()
	api.WriteOK(w, map[string]interface{}{
		"listeners": st.Listeners,
		"routes":    st.Routes,
		"states":    a.m.Status().Listeners,
	})
}

func (a *API) logs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 300 {
		n = 100
	}
	api.WriteOK(w, map[string]interface{}{"lines": a.m.AccessLogs(n)})
}

func (a *API) apply(w http.ResponseWriter, r *http.Request) {
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"listeners": states})
}

func (a *API) addListener(w http.ResponseWriter, r *http.Request) {
	var p listenerPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	l, err := a.buildListener(p, nil)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := a.store.Update(func(st *core.State) error {
		st.Listeners = append(st.Listeners, l)
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"listener": l, "states": states})
}

func (a *API) updateListener(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p listenerPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	st := a.store.Snapshot()
	var existing *core.Listener
	for i := range st.Listeners {
		if st.Listeners[i].ID == id {
			existing = &st.Listeners[i]
			break
		}
	}
	if existing == nil {
		api.WriteErr(w, http.StatusNotFound, "入口不存在")
		return
	}
	l, err := a.buildListener(p, existing)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := a.store.Update(func(s *core.State) error {
		for i := range s.Listeners {
			if s.Listeners[i].ID == id {
				s.Listeners[i] = l
				return nil
			}
		}
		return fmt.Errorf("入口不存在")
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"listener": l, "states": states})
}

func (a *API) deleteListener(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.Update(func(s *core.State) error {
		kept := make([]core.Listener, 0, len(s.Listeners))
		found := false
		for _, l := range s.Listeners {
			if l.ID == id {
				found = true
				continue
			}
			kept = append(kept, l)
		}
		if !found {
			return fmt.Errorf("入口不存在")
		}
		s.Listeners = kept
		routes := make([]core.Route, 0, len(s.Routes))
		for _, rt := range s.Routes {
			if rt.ListenerID != id {
				routes = append(routes, rt)
			}
		}
		s.Routes = routes
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"deleted": true, "note": "该入口下的路由已一并删除", "states": states})
}

func (a *API) addRoute(w http.ResponseWriter, r *http.Request) {
	var p routePayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	rt, err := a.buildRoute(p, nil)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := a.store.Update(func(s *core.State) error {
		s.Routes = append(s.Routes, rt)
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"route": rt, "states": states})
}

func (a *API) updateRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p routePayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	st := a.store.Snapshot()
	var existing *core.Route
	for i := range st.Routes {
		if st.Routes[i].ID == id {
			existing = &st.Routes[i]
			break
		}
	}
	if existing == nil {
		api.WriteErr(w, http.StatusNotFound, "路由不存在")
		return
	}
	rt, err := a.buildRoute(p, existing)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := a.store.Update(func(s *core.State) error {
		for i := range s.Routes {
			if s.Routes[i].ID == id {
				s.Routes[i] = rt
				return nil
			}
		}
		return fmt.Errorf("路由不存在")
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"route": rt, "states": states})
}

func (a *API) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.Update(func(s *core.State) error {
		kept := make([]core.Route, 0, len(s.Routes))
		found := false
		for _, rt := range s.Routes {
			if rt.ID == id {
				found = true
				continue
			}
			kept = append(kept, rt)
		}
		if !found {
			return fmt.Errorf("路由不存在")
		}
		s.Routes = kept
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	states := a.m.Apply()
	api.WriteOK(w, map[string]interface{}{"deleted": true, "states": states})
}
