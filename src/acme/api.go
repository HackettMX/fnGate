package acme

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"fngate/api"
	"fngate/core"
)

type API struct{ m *Manager }

func NewModule(m *Manager) *API { return &API{m: m} }

func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /config", a.config)
	mux.HandleFunc("GET /overview", a.overview)
	mux.HandleFunc("GET /accounts", a.listAccounts)
	mux.HandleFunc("POST /accounts", a.addAccount)
	mux.HandleFunc("DELETE /accounts/{id}", a.deleteAccount)
	mux.HandleFunc("GET /orders", a.listOrders)
	mux.HandleFunc("POST /orders", a.createOrder)
	mux.HandleFunc("GET /orders/{id}", a.orderDetail)
	mux.HandleFunc("DELETE /orders/{id}", a.deleteOrder)
	mux.HandleFunc("POST /orders/{id}/continue", a.confirmTXT)
	mux.HandleFunc("POST /orders/{id}/cancel", a.cancelOrder)
	mux.HandleFunc("POST /orders/{id}/retry", a.retryOrder)
	mux.HandleFunc("POST /renew", a.renewCert)
	mux.HandleFunc("PUT /certs/{id}", a.updateCert)
	return mux
}

func (a *API) Summarize() map[string]interface{} {
	st := a.m.store.Snapshot()
	active, failed := 0, 0
	for _, o := range st.ACMEOrders {
		switch o.Status {
		case "pending", "waiting_dns", "validating", "issuing":
			active++
		case "failed":
			failed++
		}
	}
	return map[string]interface{}{
		"orders": len(st.ACMEOrders), "active_orders": active, "failed_orders": failed,
		"providers": len(st.DNSProviders), "accounts": len(st.ACMEAccounts),
	}
}

// providerBrief 只用于订单表显示服务商名称。
type providerBrief struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type accountView struct {
	ID           string `json:"id"`
	CA           string `json:"ca"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	HasEAB       bool   `json:"has_eab"`
	CreatedAt    string `json:"created_at"`
}

func accountViewOf(x core.ACMEAccount) accountView {
	dir, err := DirectoryURL(x.CA, x.DirectoryURL)
	if err != nil {
		dir = x.DirectoryURL
	}
	return accountView{
		ID: x.ID, CA: x.CA, DirectoryURL: dir, Email: x.Email,
		HasEAB: x.EABKID != "" && x.EABHMAC != "", CreatedAt: x.CreatedAt,
	}
}

type orderView struct {
	core.ACMEOrder
	Running    bool `json:"running"`
	CanConfirm bool `json:"can_confirm"`
	Elapsed    int  `json:"elapsed_seconds"`
}

func (a *API) orderViewOf(o core.ACMEOrder) orderView {
	h := a.m.getRun(o.ID)
	v := orderView{ACMEOrder: o, Running: h != nil}
	v.CanConfirm = h != nil && h.manual != nil && len(o.ManualTXT) > 0
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", o.CreatedAt, time.Local); err == nil {
		v.Elapsed = int(time.Since(t).Seconds())
	}
	return v
}

func (a *API) config(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, map[string]interface{}{
		"cas":        CAPresets(),
		"providers":  ProviderSpecs(),
		"key_types":  []map[string]string{{"id": "ec256", "name": "ECDSA P-256（默认，推荐）"}, {"id": "rsa2048", "name": "RSA 2048（兼容旧客户端）"}},
		"challenges": []string{"dns-01"},
		"note":       "DNS-01 支持泛域名证书；HTTP-01 / TLS-ALPN-01 需要独占 80 / 443，与反代入口冲突，暂不提供。",
	})
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	st := a.m.store.Snapshot()
	// 订单表只需要「服务商 id → 名称」，完整管理在 /api/dns/providers。
	providers := make([]providerBrief, 0, len(st.DNSProviders))
	for _, p := range st.DNSProviders {
		providers = append(providers, providerBrief{ID: p.ID, Type: p.Type, Name: p.Name})
	}
	accounts := make([]accountView, 0, len(st.ACMEAccounts))
	for _, x := range st.ACMEAccounts {
		accounts = append(accounts, accountViewOf(x))
	}
	orders := make([]orderView, 0, len(st.ACMEOrders))
	for i := len(st.ACMEOrders) - 1; i >= 0; i-- {
		orders = append(orders, a.orderViewOf(st.ACMEOrders[i]))
	}
	certs := a.m.certs.List()
	auto := 0
	for _, c := range certs {
		if c.Source == "acme" && c.AutoRenew {
			auto++
		}
	}
	api.WriteOK(w, map[string]interface{}{
		"providers": providers, "accounts": accounts, "orders": orders,
		"certificates": certs, "auto_renew_certs": auto,
		"summary": a.Summarize(),
	})
}

// ---------- DNS 服务商 ----------

type providerPayload struct {
	Type   string            `json:"type"`
	Name   string            `json:"name"`
	Fields map[string]string `json:"fields"`
}

func validateProviderType(t string) (ProviderSpec, error) {
	for _, s := range ProviderSpecs() {
		if s.Type == t {
			return s, nil
		}
	}
	return ProviderSpec{}, fmt.Errorf("不支持的 DNS 服务商：%s", t)
}

// normalizeFields 统一字段名大小写与空白，避免前端多打一个空格就导致凭据失效。
func normalizeFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

// checkProviderFields 只做「本地就能判断」的格式校验；真正能不能用交给 VerifyDNS。
func checkProviderFields(spec ProviderSpec, clean map[string]string) error {
	for _, f := range spec.Fields {
		if f.Required && clean[f.Key] == "" {
			return fmt.Errorf("缺少必填项：%s", f.Label)
		}
	}
	switch spec.Type {
	case "cloudflare":
		if clean["api_token"] == "" && (clean["email"] == "" || clean["api_key"] == "") {
			return fmt.Errorf("Cloudflare 需要填写 DNS API Token，或同时填写邮箱与 Global API Key")
		}
	case "dnspod":
		// DNSPod 的凭据是「ID,Token」两段，缺逗号是一类很常见的粘贴错误。
		if t := clean["api_key"]; t != "" && !strings.Contains(t, ",") {
			return fmt.Errorf("DNSPod API Token 格式应为「ID,Token」，两段用英文逗号分隔")
		}
	}
	return nil
}

// ---------- ACME 账户 ----------

type accountPayload struct {
	CA           string `json:"ca"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	EABKID       string `json:"eab_kid"`
	EABHMAC      string `json:"eab_hmac"`
}

func (a *API) listAccounts(w http.ResponseWriter, r *http.Request) {
	st := a.m.store.Snapshot()
	out := make([]accountView, 0, len(st.ACMEAccounts))
	for _, x := range st.ACMEAccounts {
		out = append(out, accountViewOf(x))
	}
	api.WriteOK(w, map[string]interface{}{"accounts": out})
}

func (a *API) addAccount(w http.ResponseWriter, r *http.Request) {
	var p accountPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	ca := strings.TrimSpace(p.CA)
	if ca == "" {
		ca = CALetsEncrypt
	}
	dir, err := DirectoryURL(ca, p.DirectoryURL)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	acc := core.ACMEAccount{
		ID: newID(), CA: ca, DirectoryURL: dir, Email: strings.TrimSpace(p.Email),
		EABKID: strings.TrimSpace(p.EABKID), EABHMAC: strings.TrimSpace(p.EABHMAC),
		KeyPath: "", CreatedAt: nowText(),
	}
	acc.KeyPath = accountKeyPath(acc.ID)
	if err := a.m.store.Update(func(st *core.State) error {
		st.ACMEAccounts = append(st.ACMEAccounts, acc)
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	api.WriteOK(w, accountViewOf(acc))
}

func (a *API) deleteAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st := a.m.store.Snapshot()
	for _, c := range st.Certificates {
		if c.ACME != nil && c.ACME.AccountID == id {
			api.WriteErr(w, http.StatusBadRequest, "该账户正被 ACME 证书「%s」使用，不能删除", c.Name)
			return
		}
	}
	if err := a.m.store.Update(func(s *core.State) error {
		kept := make([]core.ACMEAccount, 0, len(s.ACMEAccounts))
		for _, x := range s.ACMEAccounts {
			if x.ID != id {
				kept = append(kept, x)
			}
		}
		s.ACMEAccounts = kept
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	_ = a.m.store.SecretDelete(accountKeyPath(id))
	_ = a.m.store.SecretDelete(accountRegPath(id))
	api.WriteOK(w, map[string]interface{}{"deleted": true, "note": "账户密钥与注册信息已一并删除"})
}

// ---------- 订单 ----------

func (a *API) listOrders(w http.ResponseWriter, r *http.Request) {
	st := a.m.store.Snapshot()
	out := make([]orderView, 0, len(st.ACMEOrders))
	for i := len(st.ACMEOrders) - 1; i >= 0; i-- {
		out = append(out, a.orderViewOf(st.ACMEOrders[i]))
	}
	api.WriteOK(w, map[string]interface{}{"orders": out})
}

func (a *API) createOrder(w http.ResponseWriter, r *http.Request) {
	var p OrderPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	o, err := a.m.CreateOrder(p)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, a.orderViewOf(o))
}

func (a *API) orderDetail(w http.ResponseWriter, r *http.Request) {
	o, ok := a.m.order(r.PathValue("id"))
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	api.WriteOK(w, a.orderViewOf(o))
}

func (a *API) confirmTXT(w http.ResponseWriter, r *http.Request) {
	if err := a.m.ConfirmTXT(r.PathValue("id")); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]string{"note": "已确认，正在继续校验；如果记录尚未生效，CA 可能会拒绝，可稍后重试"})
}

func (a *API) cancelOrder(w http.ResponseWriter, r *http.Request) {
	if err := a.m.Cancel(r.PathValue("id")); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"canceled": true})
}

func (a *API) retryOrder(w http.ResponseWriter, r *http.Request) {
	if err := a.m.Retry(r.PathValue("id")); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"queued": true})
}

func (a *API) deleteOrder(w http.ResponseWriter, r *http.Request) {
	if err := a.m.DeleteOrder(r.PathValue("id")); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"deleted": true})
}

type renewPayload struct {
	CertID string `json:"cert_id"`
}

func (a *API) renewCert(w http.ResponseWriter, r *http.Request) {
	var p renewPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	o, err := a.m.RenewNow(strings.TrimSpace(p.CertID))
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, a.orderViewOf(o))
}

type certUpdate struct {
	AutoRenew *bool `json:"auto_renew"`
}

func (a *API) updateCert(w http.ResponseWriter, r *http.Request) {
	var p certUpdate
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if p.AutoRenew == nil {
		api.WriteErr(w, http.StatusBadRequest, "缺少 auto_renew")
		return
	}
	if err := a.m.certs.SetAutoRenew(r.PathValue("id"), *p.AutoRenew); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"updated": true})
}
