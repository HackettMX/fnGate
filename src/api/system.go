package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"fngate/core"
)

type systemModule struct {
	s *Server
}

func newSystemModule(s *Server) *systemModule {
	return &systemModule{s: s}
}

func (m *systemModule) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", m.status)
	mux.HandleFunc("/events", m.events)
	mux.HandleFunc("/logs", m.logs)
	mux.HandleFunc("/settings", m.settings)
	mux.HandleFunc("/backup", m.backup)
	mux.HandleFunc("/backup/import", m.backupImport)
	return mux
}

func (m *systemModule) status(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	st := m.s.svc.Store.Snapshot()
	writeOK(w, map[string]interface{}{
		"version":        m.s.svc.Version,
		"uptime_seconds": int(time.Since(m.s.svc.StartedAt).Seconds()),
		"schema_version": st.SchemaVersion,
		"run_user":       core.RuntimeUser(),
		"euid":           core.EUID(),
		"can_bind_low":   core.CanBindLowPort(),
		"tasks":          m.s.svc.Scheduler.TaskNames(),
		"modules":        m.s.summary(),
		"counts": map[string]int{
			"forwards":     len(st.Forwards),
			"listeners":    len(st.Listeners),
			"routes":       len(st.Routes),
			"certificates": len(st.Certificates),
			"acme_orders":  len(st.ACMEOrders),
		},
	})
}

func (m *systemModule) events(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	writeOK(w, map[string]interface{}{"events": m.s.svc.Bus.Since(after)})
}

func (m *systemModule) logs(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 1000 {
		n = 200
	}
	writeOK(w, map[string]interface{}{"lines": m.s.svc.Logger.Tail(n)})
}

func (m *systemModule) settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		st := m.s.svc.Store.Snapshot()
		writeOK(w, st.Settings)
	case http.MethodPut:
		var p core.Settings
		if err := decodeJSON(r, &p); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		level := strings.ToUpper(strings.TrimSpace(p.LogLevel))
		switch level {
		case "DEBUG", "INFO", "WARN", "ERROR":
		default:
			writeErr(w, http.StatusBadRequest, "日志级别只能是 DEBUG / INFO / WARN / ERROR")
			return
		}
		p.LogLevel = level
		if p.ReapplyInterval < 15 || p.ReapplyInterval > 3600 {
			writeErr(w, http.StatusBadRequest, "自动补发间隔需在 15-3600 秒之间")
			return
		}
		if p.RenewDays < 7 || p.RenewDays > 60 {
			writeErr(w, http.StatusBadRequest, "续期提前天数需在 7-60 天之间")
			return
		}
		if p.RenewHour < 0 || p.RenewHour > 23 || p.HealthInterval < 10 || p.HealthInterval > 3600 {
			writeErr(w, http.StatusBadRequest, "续期小时或健康检查间隔超出范围")
			return
		}
		p.DNSCheckMode = strings.ToLower(strings.TrimSpace(p.DNSCheckMode))
		switch p.DNSCheckMode {
		case "", "auto":
			p.DNSCheckMode = "auto"
		case "strict", "recursive":
		default:
			writeErr(w, http.StatusBadRequest, "DNS 传播校验方式只能是 auto / strict / recursive")
			return
		}
		if p.DNSWaitSec == 0 {
			p.DNSWaitSec = 180
		}
		if p.DNSWaitSec < 60 || p.DNSWaitSec > 1800 {
			writeErr(w, http.StatusBadRequest, "DNS 传播检查最长等待需在 60-1800 秒之间")
			return
		}
		cleaned := make([]string, 0, len(p.DNSResolvers))
		for _, r := range p.DNSResolvers {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			if len(r) > 253 || strings.ContainsAny(r, " \t/") {
				writeErr(w, http.StatusBadRequest, "自定义 DNS 地址格式不正确："+r)
				return
			}
			cleaned = append(cleaned, r)
		}
		p.DNSResolvers = cleaned
		if err := m.s.svc.Store.Update(func(st *core.State) error {
			st.Settings = p
			return nil
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		m.s.svc.Logger.SetLevel(level)
		m.s.svc.Bus.Publish("system", "info", "设置已更新（日志级别 %s）", level)
		writeOK(w, p)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的请求方法 %s", r.Method)
	}
}

func (m *systemModule) backup(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=fngate-state.json")
	if err := m.s.svc.Store.Export(w); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	m.s.svc.Bus.Publish("system", "info", "已导出配置备份（不含私钥与凭据）")
}

func (m *systemModule) backupImport(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if err := m.s.svc.Store.Import(r.Body); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	m.s.svc.Bus.Publish("system", "warn", "已从备份导入配置，模块将按新配置重新生效")
	writeOK(w, map[string]string{"note": "私钥与 DNS 凭据不在备份内，如有 ACME 证书请重新配置凭据"})
}
