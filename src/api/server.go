package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"fngate/core"
)

// Module 是每个业务模块挂载到 /api/<name>/ 下的契约。
type Module interface {
	Routes() http.Handler
	Summarize() map[string]interface{}
}

type Services struct {
	Store     *core.Store
	Bus       *core.EventBus
	Logger    *core.Logger
	Scheduler *core.Scheduler
	Version   string
	StartedAt time.Time
}

type Server struct {
	svc     *Services
	secure  *Secure
	static  fs.FS
	base    string
	modules map[string]Module
	system  *systemModule
}

func New(svc *Services, staticFS fs.FS) *Server {
	s := &Server{
		svc:     svc,
		secure:  newSecure(),
		static:  staticFS,
		base:    "/",
		modules: map[string]Module{},
	}
	s.system = newSystemModule(s)
	return s
}

func (s *Server) Mount(name string, m Module) {
	s.modules[name] = m
}

func (s *Server) CSRF() string { return s.secure.Token() }

func (s *Server) summary() map[string]interface{} {
	out := map[string]interface{}{}
	for name, m := range s.modules {
		out[name] = m.Summarize()
	}
	return out
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w, map[string]interface{}{
			"status": "ok", "version": s.svc.Version,
			"uptime": int(time.Since(s.svc.StartedAt).Seconds()),
		})
	})
	mux.Handle("/api/system/", http.StripPrefix("/api/system", s.system.Routes()))
	for name, m := range s.modules {
		mux.Handle("/api/"+name+"/", http.StripPrefix("/api/"+name, m.Routes()))
	}
	mux.Handle("/static/", http.StripPrefix("/static", s.staticHandler()))
	mux.Handle("/", s.staticHandler())
	return s.secure.Wrap(s.requestLogger(mux))
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if s.svc.Logger != nil {
			s.svc.Logger.Debug("api %s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Truncate(time.Millisecond))
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.static))
	base := s.base
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "frame-ancestors *")
		if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, "/index.html") {
			if raw, err := fs.ReadFile(s.static, "index.html"); err == nil {
				page := strings.ReplaceAll(string(raw), "{{VERSION}}", s.svc.Version)
				page = strings.ReplaceAll(page, "{{BASE}}", base)
				page = strings.ReplaceAll(page, "{{CSRF}}", s.CSRF())
				w.Header().Set("Cache-Control", "no-cache, must-revalidate")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(page))
				return
			}
		}
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// SetGatewayPrefix 由 main 注入，用于生成页面 <base>。
func (s *Server) SetGatewayPrefix(prefix string) {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		s.base = "/"
	} else {
		s.base = prefix + "/"
	}
}

func (s *Server) Describe() string {
	return fmt.Sprintf("modules=%d", len(s.modules))
}
