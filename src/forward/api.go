package forward

import (
	"net/http"
	"strconv"
	"strings"

	"fngate/api"
)

type API struct {
	m *Manager
}

func NewModule(m *Manager) *API { return &API{m: m} }

func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", a.status)
	mux.HandleFunc("POST /discover", a.discover)
	mux.HandleFunc("GET /mappings", a.mappings)
	mux.HandleFunc("POST /mappings", a.add)
	mux.HandleFunc("DELETE /mappings/{id}", a.delete)
	mux.HandleFunc("POST /mappings/{id}/enable", a.enable)
	mux.HandleFunc("DELETE /external/{port}/{proto}", a.deleteExternal)
	mux.HandleFunc("POST /reapply", a.reapply)
	return mux
}

func (a *API) Summarize() map[string]interface{} { return a.m.Summarize() }

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, a.m.Status(false))
}

func (a *API) discover(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, a.m.Discover())
}

func (a *API) mappings(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, a.m.Mappings())
}

func (a *API) add(w http.ResponseWriter, r *http.Request) {
	var p AddPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	f, err := a.m.Add(p)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, f)
}

func (a *API) delete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	warning, err := a.m.Delete(id)
	if err != nil {
		api.WriteErr(w, http.StatusNotFound, "%v", err)
		return
	}
	api.WriteOK(w, map[string]string{"warning": warning})
}

func (a *API) enable(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if err := a.m.Enable(id); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"enabled": true})
}

func (a *API) deleteExternal(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "端口格式不正确")
		return
	}
	if err := a.m.DeleteExternal(port, r.PathValue("proto")); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"deleted": true})
}

func (a *API) reapply(w http.ResponseWriter, r *http.Request) {
	count, err := a.m.Reapply(true)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]interface{}{"reapplied": count})
}
