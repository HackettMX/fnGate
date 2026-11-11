package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"fngate/core"
)

type proxyEntry struct {
	rp      *httputil.ReverseProxy
	backend Backend
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func routeSignature(r core.Route) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (m *Manager) getProxy(r core.Route, incoming string) (*proxyEntry, error) {
	key := routeSignature(r)
	if v, ok := m.proxyCache.Load(key); ok {
		return v.(*proxyEntry), nil
	}
	bd, err := ParseBackend(r.Backend, "http")
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(r.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
	}
	if bd.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: !r.VerifyBackendTLS,
			MinVersion:         tls.VersionTLS12,
		}
	}
	prefix := NormalizePathPrefix(r.PathPrefix)
	strip := r.StripPrefix && prefix != ""
	headers := r.RequestHeaders
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			originalHost := req.Host
			req.URL.Scheme = bd.Scheme
			req.URL.Host = bd.Host
			if strip {
				p := req.URL.Path
				if strings.HasPrefix(p, prefix) {
					p = p[len(prefix):]
				}
				if p == "" {
					p = "/"
				}
				req.URL.Path = p
				req.URL.RawPath = ""
			}
			req.URL.Path = singleJoiningSlash(bd.BasePath, req.URL.Path)
			req.Host = bd.Host
			if req.Header.Get("X-Forwarded-Host") == "" {
				req.Header.Set("X-Forwarded-Host", originalHost)
			}
			if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", incoming)
			}
			if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				req.Header.Set("X-Real-IP", host)
			}
			for k, v := range headers {
				if strings.TrimSpace(v) == "" {
					req.Header.Del(k)
				} else {
					req.Header.Set(k, v)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			m.log.Warn("转发到 %s 失败: %v", bd.URL(), err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, "fnGate: 无法连接后端 %s\n%v\n", bd.URL(), err)
		},
	}
	entry := &proxyEntry{rp: rp, backend: bd}
	actual, _ := m.proxyCache.LoadOrStore(key, entry)
	return actual.(*proxyEntry), nil
}

func (m *Manager) pruneCache(valid map[string]bool) {
	m.proxyCache.Range(func(key, _ interface{}) bool {
		if !valid[key.(string)] {
			m.proxyCache.Delete(key)
		}
		return true
	})
}

func (m *Manager) httpsURL(view *runtimeView, req *http.Request) string {
	host := StripHostPort(req.Host)
	for _, l := range view.listeners {
		if l.Protocol == "https" && l.Enabled {
			if l.Port != 443 {
				host = net.JoinHostPort(host, strconv.Itoa(l.Port))
			}
			break
		}
	}
	return "https://" + host + req.URL.RequestURI()
}

func (m *Manager) buildHTTPHandler(listenerID, scheme string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		view, ok := m.view.Load().(*runtimeView)
		if !ok {
			http.Error(w, "fnGate: 代理配置尚未就绪", http.StatusServiceUnavailable)
			return
		}
		l, ok := view.listeners[listenerID]
		if !ok {
			http.Error(w, "fnGate: 入口不存在", http.StatusServiceUnavailable)
			return
		}
		if scheme == "http" && l.TLS.RedirectHTTP {
			http.Redirect(w, req, m.httpsURL(view, req), http.StatusMovedPermanently)
			m.access(req, http.StatusMovedPermanently, "redirect", "https", 0)
			return
		}
		if scheme == "https" && l.TLS.HSTS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r, found := pickRoute(view.routes[listenerID], req.Host, req.URL.Path)
		if !found {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rec.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, "fnGate: 没有匹配的路由\n\n请求: %s%s\n入口端口: %d (%s)\n\n请检查「反向代理」中该入口下的域名与路径前缀。\n",
				req.Host, req.URL.Path, l.Port, l.Protocol)
			m.access(req, http.StatusNotFound, "-", "-", time.Since(start))
			return
		}
		if !r.Websocket && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			rec.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, "fnGate: 该路由未开启 WebSocket 支持")
			m.access(req, http.StatusBadRequest, r.Name, "-", time.Since(start))
			return
		}
		entry, err := m.getProxy(r, scheme)
		if err != nil {
			rec.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, "fnGate: 后端配置无效: %v", err)
			m.access(req, http.StatusBadGateway, r.Name, "-", time.Since(start))
			return
		}
		entry.rp.ServeHTTP(rec, req)
		m.access(req, rec.status, r.Name, entry.backend.URL(), time.Since(start))
	})
}

func (m *Manager) access(req *http.Request, status int, route, backend string, d time.Duration) {
	if !m.accessEnabled.Load() {
		return
	}
	line := fmt.Sprintf("%s %s %s %s -> %d %s %s",
		time.Now().Format("15:04:05"), req.Method, req.Host, req.URL.Path,
		status, backend, d.Truncate(time.Millisecond))
	m.accessMu.Lock()
	m.accessLines = append(m.accessLines, line)
	if len(m.accessLines) > 300 {
		m.accessLines = append([]string(nil), m.accessLines[len(m.accessLines)-300:]...)
	}
	m.accessMu.Unlock()
	m.log.Info("access %s route=%s", line, route)
}

func (m *Manager) AccessLogs(n int) []string {
	m.accessMu.Lock()
	defer m.accessMu.Unlock()
	if n <= 0 || n > len(m.accessLines) {
		n = len(m.accessLines)
	}
	out := make([]string, n)
	copy(out, m.accessLines[len(m.accessLines)-n:])
	return out
}
