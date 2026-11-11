package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	alidns "github.com/alibabacloud-go/alidns-20150109/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudflare/cloudflare-go"

	"fngate/api"
	"fngate/core"
)

// DNSAPI 是独立的「DNS 服务商」模块，挂载在 /api/dns/ 下。
//
// 物理上仍与 acme 同包（复用凭据校验、只读探测这些实现，避免两份判定标准），
// 但对外是独立模块、独立路由前缀，前端也是独立页面。等 P2 引入域名解析时
// 再把这些能力下沉到 dnsp 公共包。
type DNSAPI struct{ m *Manager }

func NewDNSModule(m *Manager) *DNSAPI { return &DNSAPI{m: m} }

func (a *DNSAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /providers", a.list)
	mux.HandleFunc("POST /providers", a.add)
	mux.HandleFunc("PUT /providers/{id}", a.update)
	mux.HandleFunc("DELETE /providers/{id}", a.remove)
	mux.HandleFunc("POST /providers/verify", a.verify)
	mux.HandleFunc("POST /providers/{id}/verify", a.verifySaved)
	mux.HandleFunc("GET /providers/{id}/zones", a.zones)
	mux.HandleFunc("GET /types", a.types)
	// 域名解析（P2）：查询与体检都是只读，不改任何 DNS 记录。
	mux.HandleFunc("GET /resolvers", a.resolvers)
	mux.HandleFunc("POST /resolve/query", a.resolveQuery)
	mux.HandleFunc("POST /resolve/diagnose", a.diagnose)
	return mux
}

func (a *DNSAPI) Summarize() map[string]interface{} {
	st := a.m.store.Snapshot()
	checked, failing := 0, 0
	for _, p := range st.DNSProviders {
		if p.LastCheckAt == "" {
			continue
		}
		checked++
		if !p.LastCheckOK {
			failing++
		}
	}
	return map[string]interface{}{
		"providers": len(st.DNSProviders), "checked": checked, "failing": failing,
	}
}

type dnsProviderView struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	TypeName     string `json:"type_name"`
	Name         string `json:"name"`
	Configured   bool   `json:"configured"`
	AccountHint  string `json:"account_hint"`
	LastCheckAt  string `json:"last_check_at"`
	LastCheckOK  bool   `json:"last_check_ok"`
	LastCheckMsg string `json:"last_check_msg"`
	ZoneCount    int    `json:"zone_count"`
	CertCount    int    `json:"cert_count"`
	OrderCount   int    `json:"order_count"`
	CreatedAt    string `json:"created_at"`
}

func (a *DNSAPI) viewOf(p core.DNSProvider, st core.State) dnsProviderView {
	v := dnsProviderView{
		ID: p.ID, Type: p.Type, Name: p.Name,
		Configured:   p.Type == "manual" || p.CredentialRef != "",
		AccountHint:  p.AccountHint,
		LastCheckAt:  p.LastCheckAt,
		LastCheckOK:  p.LastCheckOK,
		LastCheckMsg: p.LastCheckMsg,
		ZoneCount:    p.ZoneCount,
		CreatedAt:    p.CreatedAt,
		TypeName:     typeNameOf(p.Type),
	}
	for _, c := range st.Certificates {
		if c.ACME != nil && c.ACME.ProviderID == p.ID {
			v.CertCount++
		}
	}
	for _, o := range st.ACMEOrders {
		if o.ProviderID == p.ID && isActiveOrder(o.Status) {
			v.OrderCount++
		}
	}
	return v
}

func typeNameOf(t string) string {
	for _, s := range ProviderSpecs() {
		if s.Type == t {
			return s.Name
		}
	}
	return t
}

func isActiveOrder(s string) bool {
	switch s {
	case "pending", "waiting_dns", "validating", "issuing":
		return true
	}
	return false
}

func (a *DNSAPI) list(w http.ResponseWriter, r *http.Request) {
	st := a.m.store.Snapshot()
	out := make([]dnsProviderView, 0, len(st.DNSProviders))
	for _, p := range st.DNSProviders {
		out = append(out, a.viewOf(p, st))
	}
	api.WriteOK(w, map[string]interface{}{"providers": out})
}

func (a *DNSAPI) types(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, map[string]interface{}{"types": ProviderSpecs()})
}

func (a *DNSAPI) findProvider(id string) (*core.DNSProvider, core.State, bool) {
	st := a.m.store.Snapshot()
	for i := range st.DNSProviders {
		if st.DNSProviders[i].ID == id {
			return &st.DNSProviders[i], st, true
		}
	}
	return nil, st, false
}

// verify 供「添加服务商」弹窗里的「测试连接」按钮调用：只探测，不落库、不写 DNS。
func (a *DNSAPI) verify(w http.ResponseWriter, r *http.Request) {
	var p providerPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	spec, err := validateProviderType(p.Type)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	clean := normalizeFields(p.Fields)
	if err := checkProviderFields(spec, clean); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	res := VerifyDNS(p.Type, clean)
	if !res.OK {
		api.WriteErr(w, http.StatusBadRequest, "%s", res.Message)
		return
	}
	api.WriteOK(w, res)
}

// verifySaved 对已保存的服务商重跑只读探测，并把结果落库，
// 这样列表页展示的状态不是每次请求都打一次外网。
func (a *DNSAPI) verifySaved(w http.ResponseWriter, r *http.Request) {
	p, _, ok := a.findProvider(r.PathValue("id"))
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "DNS 服务商不存在")
		return
	}
	if p.Type == "manual" {
		res := VerifyResult{OK: true, Message: "手动 TXT 模式无需凭据，申请时按提示添加记录即可"}
		a.markCheck(p.ID, res)
		api.WriteOK(w, res)
		return
	}
	if p.CredentialRef == "" {
		api.WriteErr(w, http.StatusBadRequest, "该服务商还没有保存凭据")
		return
	}
	raw, err := a.m.store.SecretRead(p.CredentialRef)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "读取凭据失败（可能从备份恢复后凭据丢失），请重新添加该服务商")
		return
	}
	var cred credentials
	if err := json.Unmarshal(raw, &cred); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "凭据格式损坏，请重新添加该服务商")
		return
	}
	res := VerifyDNS(p.Type, cred)
	a.markCheck(p.ID, res)
	if !res.OK {
		api.WriteErr(w, http.StatusBadRequest, "%s", res.Message)
		return
	}
	api.WriteOK(w, res)
}

func (a *DNSAPI) markCheck(id string, res VerifyResult) {
	_ = a.m.store.Update(func(st *core.State) error {
		for i := range st.DNSProviders {
			if st.DNSProviders[i].ID != id {
				continue
			}
			st.DNSProviders[i].LastCheckAt = nowText()
			st.DNSProviders[i].LastCheckOK = res.OK
			if res.OK {
				st.DNSProviders[i].LastCheckMsg = res.Message
			} else {
				st.DNSProviders[i].LastCheckMsg = res.Message
			}
			return nil
		}
		return nil
	})
}

func (a *DNSAPI) add(w http.ResponseWriter, r *http.Request) {
	var p providerPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	spec, err := validateProviderType(p.Type)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	clean := normalizeFields(p.Fields)
	if err := checkProviderFields(spec, clean); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	// 保存前先跑一次只读连通性校验：配一个连不通的服务商，等到申请证书时才报错更难排查。
	res := VerifyDNS(p.Type, clean)
	if !res.OK {
		api.WriteErr(w, http.StatusBadRequest, "凭据校验未通过：%s", res.Message)
		return
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = spec.Name
	}
	id := newID()
	ref := ""
	if p.Type != "manual" {
		raw, err := json.Marshal(clean)
		if err != nil {
			api.WriteErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		ref = dnsCredentialPath(id)
		if err := a.m.store.SecretWrite(ref, raw); err != nil {
			api.WriteErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
	}
	rec := core.DNSProvider{
		ID: id, Type: p.Type, Name: name, CredentialRef: ref,
		AccountHint: accountHintOf(p.Type, credentials(clean)),
		LastCheckAt: nowText(), LastCheckOK: true, LastCheckMsg: res.Message,
		CreatedAt: nowText(),
	}
	if err := a.m.store.Update(func(st *core.State) error {
		st.DNSProviders = append(st.DNSProviders, rec)
		return nil
	}); err != nil {
		_ = a.m.store.SecretDelete(ref)
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	a.m.publish("info", "已配置 DNS 服务商「%s」", name)
	st := a.m.store.Snapshot()
	api.WriteOK(w, a.viewOf(rec, st))
}

type providerUpdatePayload struct {
	Name   string            `json:"name"`
	Fields map[string]string `json:"fields"`
}

// update 支持改名与覆盖凭据。覆盖凭据时重新校验，避免把可用凭据改成失效的。
func (a *DNSAPI) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found, _, ok := a.findProvider(id)
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "DNS 服务商不存在")
		return
	}
	var p providerUpdatePayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	name := strings.TrimSpace(p.Name)
	var newRef, newHint string
	var check *VerifyResult

	if len(p.Fields) > 0 {
		spec, err := validateProviderType(found.Type)
		if err != nil {
			api.WriteErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		clean := normalizeFields(p.Fields)
		if err := checkProviderFields(spec, clean); err != nil {
			api.WriteErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		res := VerifyDNS(found.Type, clean)
		check = &res
		if !res.OK {
			api.WriteErr(w, http.StatusBadRequest, "凭据校验未通过：%s", res.Message)
			return
		}
		raw, err := json.Marshal(clean)
		if err != nil {
			api.WriteErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if err := a.m.store.SecretWrite(dnsCredentialPath(id), raw); err != nil {
			api.WriteErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		newRef = dnsCredentialPath(id)
		newHint = accountHintOf(found.Type, credentials(clean))
	}

	if err := a.m.store.Update(func(st *core.State) error {
		for i := range st.DNSProviders {
			if st.DNSProviders[i].ID != id {
				continue
			}
			if name != "" {
				st.DNSProviders[i].Name = name
			}
			if newRef != "" {
				st.DNSProviders[i].CredentialRef = newRef
				st.DNSProviders[i].AccountHint = newHint
				st.DNSProviders[i].ZoneCount = 0
			}
			if check != nil {
				st.DNSProviders[i].LastCheckAt = nowText()
				st.DNSProviders[i].LastCheckOK = check.OK
				st.DNSProviders[i].LastCheckMsg = check.Message
			}
			return nil
		}
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	a.m.publish("info", "已更新 DNS 服务商「%s」", id)
	updated, st, _ := a.findProvider(id)
	api.WriteOK(w, a.viewOf(*updated, st))
}

func (a *DNSAPI) remove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found, st, ok := a.findProvider(id)
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "DNS 服务商不存在")
		return
	}
	// 有证书或进行中的任务引用时不允许删除，否则自动续期会静默失效。
	var certNames []string
	for _, c := range st.Certificates {
		if c.ACME != nil && c.ACME.ProviderID == id {
			certNames = append(certNames, c.Name)
		}
	}
	if len(certNames) > 0 {
		api.WriteErr(w, http.StatusConflict,
			"该服务商正被 %d 张证书用于自动续期（%s），请先改用其它服务商或删除这些证书",
			len(certNames), strings.Join(certNames, "、"))
		return
	}
	for _, o := range st.ACMEOrders {
		if o.ProviderID == id && isActiveOrder(o.Status) {
			api.WriteErr(w, http.StatusConflict, "该服务商有正在执行的申请任务，请等待任务结束后再删除")
			return
		}
	}
	if err := a.m.store.Update(func(st *core.State) error {
		out := st.DNSProviders[:0]
		for _, p := range st.DNSProviders {
			if p.ID != id {
				out = append(out, p)
			}
		}
		st.DNSProviders = out
		return nil
	}); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if found.CredentialRef != "" {
		_ = a.m.store.SecretDelete(found.CredentialRef)
	}
	a.m.publish("warn", "已删除 DNS 服务商「%s」", found.Name)
	api.WriteOK(w, map[string]bool{"deleted": true})
}

// zones 列出该账号下可管理的域名。只读，用于「查看域名」抽屉，
// 让用户在申请证书前就能确认域名到底托管在哪个账号。
func (a *DNSAPI) zones(w http.ResponseWriter, r *http.Request) {
	p, _, ok := a.findProvider(r.PathValue("id"))
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "DNS 服务商不存在")
		return
	}
	if p.Type == "manual" {
		api.WriteOK(w, map[string]interface{}{"zones": []string{}, "note": "手动 TXT 模式没有可列举的域名"})
		return
	}
	raw, err := a.m.store.SecretRead(p.CredentialRef)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "读取凭据失败，请重新添加该服务商")
		return
	}
	var cred credentials
	if err := json.Unmarshal(raw, &cred); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "凭据格式损坏，请重新添加该服务商")
		return
	}
	zones, err := listZonesOf(p.Type, cred)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%s", err.Error())
		return
	}
	sort.Strings(zones)
	_ = a.m.store.Update(func(st *core.State) error {
		for i := range st.DNSProviders {
			if st.DNSProviders[i].ID == p.ID {
				st.DNSProviders[i].ZoneCount = len(zones)
				return nil
			}
		}
		return nil
	})
	api.WriteOK(w, map[string]interface{}{"zones": zones, "count": len(zones), "total": len(zones)})
}

// ---------- 辅助 ----------

// accountHintOf 生成脱敏后的账号标识，让列表页能区分同类型的多个账号，
// 又不把凭据明文送到前端。
func accountHintOf(pType string, cred credentials) string {
	switch pType {
	case "dnspod":
		t := cred.get("api_key")
		if i := strings.Index(t, ","); i > 0 {
			return t[:i] + "," + maskSecret(t[i+1:])
		}
		return maskSecret(t)
	case "alidns":
		return maskSecret(cred.get("access_key"))
	case "cloudflare":
		if t := cred.get("api_token"); t != "" {
			return maskSecret(t)
		}
		return cred.get("email")
	}
	return ""
}

func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 6 {
		return "***"
	}
	return s[:6] + "***"
}

// listZonesOf 用各家的只读接口列出账号下的域名。
func listZonesOf(pType string, cred credentials) ([]string, error) {
	switch pType {
	case "alidns":
		return listAliZones(cred)
	case "dnspod":
		token := cred.get("api_key")
		if token == "" {
			return nil, fmt.Errorf("DNSPod 缺少 API Token")
		}
		zones, err := newDNSPodAPI(token).listZones()
		if err != nil {
			var apiErr *dnspodAPIError
			if errors.As(err, &apiErr) {
				return nil, fmt.Errorf("%s", newDNSPodError("读取域名列表", apiErr.Code, apiErr.Message).Human())
			}
			return nil, fmt.Errorf("调用 DNSPod 接口失败：%w", err)
		}
		out := make([]string, 0, len(zones))
		for _, z := range zones {
			out = append(out, z.Name)
		}
		return out, nil
	case "cloudflare":
		api, err := cloudflareClient(cred)
		if err != nil {
			return nil, err
		}
		res, err := cfListZones(api)
		if err != nil {
			return nil, fmt.Errorf("%s", humanizeCFErr(err))
		}
		out := make([]string, 0, len(res))
		for _, z := range res {
			out = append(out, z.Name)
		}
		return out, nil
	}
	return nil, fmt.Errorf("该服务商不支持列举域名")
}

func listAliZones(cred credentials) ([]string, error) {
	ak, sk := cred.get("access_key"), cred.get("secret_key")
	if ak == "" || sk == "" {
		return nil, fmt.Errorf("阿里云 DNS 缺少 AccessKey ID / Secret")
	}
	region := cred.get("region_id")
	if region == "" {
		region = "cn-hangzhou"
	}
	cfg := new(openapi.Config).
		SetRegionId(region).
		SetAccessKeyId(ak).
		SetAccessKeySecret(sk).
		SetConnectTimeout(8000).
		SetReadTimeout(15000)
	if sts := cred.get("security_token"); sts != "" {
		cfg.SetSecurityToken(sts)
	}
	client, err := alidns.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("初始化阿里云客户端失败：%w", err)
	}
	var out []string
	var page int64 = 1
	for {
		resp, err := client.DescribeDomains(&alidns.DescribeDomainsRequest{
			PageNumber: tea.Int64(page),
			PageSize:   tea.Int64(100),
		})
		if err != nil {
			return nil, fmt.Errorf("%s", humanizeAliErr(err))
		}
		if resp == nil || resp.Body == nil || resp.Body.Domains == nil || resp.Body.Domains.Domain == nil {
			break
		}
		items := resp.Body.Domains.Domain
		if len(items) == 0 {
			break
		}
		for _, d := range items {
			if d != nil && d.DomainName != nil && *d.DomainName != "" {
				out = append(out, *d.DomainName)
			}
		}
		if len(items) < 100 {
			break
		}
		page++
		if page > 50 {
			break
		}
	}
	return out, nil
}

func cloudflareClient(cred credentials) (*cloudflare.API, error) {
	token, email, key := cred.get("api_token"), cred.get("email"), cred.get("api_key")
	switch {
	case token != "":
		return cloudflare.NewWithAPIToken(token)
	case email != "" && key != "":
		return cloudflare.New(key, email)
	}
	return nil, fmt.Errorf("Cloudflare 需要 DNS API Token，或同时提供邮箱与 Global API Key")
}

// ---------- 域名解析（P2，只读） ----------

type resolveQueryPayload struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Servers []string `json:"servers"`
	Follow  *bool    `json:"follow"`
}

type resolveDiagnosePayload struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
}

// resolvers 返回「服务器」多选的候选与默认勾选。
func (a *DNSAPI) resolvers(w http.ResponseWriter, r *http.Request) {
	st := a.m.store.Snapshot()
	system := systemResolvers()
	selected := effectiveResolvers(st.Settings.DNSResolvers)
	if len(selected) > 5 {
		selected = selected[:5]
	}
	api.WriteOK(w, map[string]interface{}{
		"system":     system,
		"custom":     st.Settings.DNSResolvers,
		"presets":    presetResolvers,
		"selected":   selected,
		"types":      resolveRecordTypes,
		"check_mode": st.Settings.DNSCheckMode,
	})
}

// serverList 决定本次查询用哪些服务器：请求显式传入优先，否则用设置里的。
func (a *DNSAPI) serverList(in []string) []string {
	if len(in) > 0 {
		return normalizeResolvers(in)
	}
	return effectiveResolvers(a.m.store.Snapshot().Settings.DNSResolvers)
}

func (a *DNSAPI) resolveQuery(w http.ResponseWriter, r *http.Request) {
	var p resolveQueryPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	follow := true
	if p.Follow != nil {
		follow = *p.Follow
	}
	res, err := runResolveQuery(p.Name, p.Type, a.serverList(p.Servers), follow)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, res)
}

func (a *DNSAPI) diagnose(w http.ResponseWriter, r *http.Request) {
	var p resolveDiagnosePayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	res, err := runDiagnose(p.Domain, a.serverList(p.Servers))
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, res)
}
