package cert

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fngate/api"
	"fngate/core"
)

type API struct{ m *Manager }

func NewModule(m *Manager) *API { return &API{m: m} }

func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /list", a.list)
	mux.HandleFunc("GET /status", a.status)
	mux.HandleFunc("POST /upload", a.upload)
	mux.HandleFunc("POST /selfsigned", a.selfsigned)
	mux.HandleFunc("POST /fnos/sync", a.fnosSync)
	mux.HandleFunc("POST /default", a.setDefault)
	mux.HandleFunc("GET /{id}", a.detail)
	mux.HandleFunc("GET /{id}/references", a.references)
	mux.HandleFunc("GET /{id}/download", a.download)
	mux.HandleFunc("POST /{id}/export", a.exportBundle)
	mux.HandleFunc("PUT /{id}", a.update)
	mux.HandleFunc("DELETE /{id}", a.remove)
	return mux
}

func (a *API) Summarize() map[string]interface{} {
	st := a.m.Store().Snapshot()
	expiring, expired := 0, 0
	for _, c := range st.Certificates {
		_, s := a.m.ExpiryOf(c.NotAfter)
		if s == "expiring" {
			expiring++
		} else if s == "expired" {
			expired++
		}
	}
	return map[string]interface{}{
		"certificates": len(st.Certificates), "expiring": expiring, "expired": expired,
		"acme_orders": len(st.ACMEOrders),
	}
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	views := a.m.List()
	expiring, expired, missing := 0, 0, 0
	for _, v := range views {
		switch v.Status {
		case "expiring":
			expiring++
		case "expired":
			expired++
		case "missing":
			missing++
		}
	}
	st := a.m.Store().Snapshot()
	failing := make([]map[string]string, 0)
	for _, o := range st.ACMEOrders {
		if o.Status == "failed" {
			failing = append(failing, map[string]string{"id": o.ID, "name": strings.Join(o.Domains, ", "), "error": o.Error})
		}
	}
	syncedAt, snapshotCount := a.m.SnapshotInfo()
	// 到期阈值跟随设置里的「续期提前天数」，前端文案据此显示，不写死 30 天。
	expiringDays := st.Settings.RenewDays
	if expiringDays <= 0 {
		expiringDays = 30
	}
	api.WriteOK(w, map[string]interface{}{
		"certificates":    views,
		"expiring":        expiring,
		"expired":         expired,
		"missing":         missing,
		"expiring_days":   expiringDays,
		"default_cert_id": st.Settings.DefaultCertID,
		"failing_orders":  failing,
		"fnos_synced_at":  syncedAt,
		"fnos_snapshot":   snapshotCount,
	})
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	api.WriteOK(w, a.Summarize())
}

type uploadPayload struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (a *API) upload(w http.ResponseWriter, r *http.Request) {
	var p uploadPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	certPEM := []byte(strings.TrimSpace(p.CertPEM))
	keyPEM := []byte(strings.TrimSpace(p.KeyPEM))
	c, err := a.m.AddManual(p.Name, certPEM, keyPEM)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	a.m.Bus().Publish("cert", "info", "已上传证书「%s」（%s）", c.Name, c.PrimaryDomain)
	api.WriteOK(w, map[string]interface{}{"certificate": c.ID, "name": c.Name})
}

type selfSignedPayload struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

func (a *API) selfsigned(w http.ResponseWriter, r *http.Request) {
	var p selfSignedPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	domains := make([]string, 0, len(p.Domains))
	for _, d := range p.Domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "\r\n/\\") || len(d) > 253 {
			api.WriteErr(w, http.StatusBadRequest, "域名不合法：%s", d)
			return
		}
		domains = append(domains, d)
	}
	c, err := a.m.AddSelfSigned(p.Name, domains)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	a.m.Bus().Publish("cert", "warn", "已生成自签证书「%s」，浏览器不会信任，仅建议内网临时使用", c.Name)
	api.WriteOK(w, map[string]interface{}{"certificate": c.ID, "name": c.Name})
}

func (a *API) fnosSync(w http.ResponseWriter, r *http.Request) {
	res, err := a.m.Sync()
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	a.m.Bus().Publish("cert", "info", "已执行飞牛系统证书同步")
	api.WriteOK(w, res)
}

type defaultPayload struct {
	ID string `json:"id"`
}

func (a *API) setDefault(w http.ResponseWriter, r *http.Request) {
	var p defaultPayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := a.m.SetDefault(strings.TrimSpace(p.ID)); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if p.ID == "" {
		api.WriteOK(w, map[string]string{"note": "已取消默认证书，未指定证书的 HTTPS 入口将按 SNI 自动匹配或回退自签"})
		return
	}
	api.WriteOK(w, map[string]string{"note": "已设为默认证书，对所有未指定证书的 HTTPS 入口立即生效"})
}

func (a *API) detail(w http.ResponseWriter, r *http.Request) {
	c, ok := a.m.ByID(r.PathValue("id"))
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "证书不存在")
		return
	}
	chain, err := a.m.ReadChain(c)
	if err != nil {
		chain = []byte("（证书文件缺失，无法读取证书链）")
	}
	views := a.m.List()
	var view View
	for _, v := range views {
		if v.ID == c.ID {
			view = v
			break
		}
	}
	api.WriteOK(w, map[string]interface{}{
		"certificate": view,
		"chain":       string(chain),
		"references":  a.m.References(c.ID),
	})
}

func (a *API) references(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.m.ByID(r.PathValue("id")); !ok {
		api.WriteErr(w, http.StatusNotFound, "证书不存在")
		return
	}
	api.WriteOK(w, map[string]interface{}{"items": a.m.References(r.PathValue("id"))})
}

// download 只返回公钥证书链，永远不暴露私钥文件。
func (a *API) download(w http.ResponseWriter, r *http.Request) {
	c, ok := a.m.ByID(r.PathValue("id"))
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "证书不存在")
		return
	}
	chain, err := a.m.ReadChain(c)
	if err != nil {
		api.WriteErr(w, http.StatusNotFound, "%v", err)
		return
	}
	name := strings.ReplaceAll(c.Name, "/", "_")
	w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pem"`, name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(chain)
}

// exportBundle 把「证书链 + 私钥」打包成 ZIP，供导入飞牛系统证书等外部场景使用。
// 只接受 POST：这样必须过同源校验与 CSRF Token，避免被第三方页面诱导下载私钥。
// GET 的 download 永远只吐公钥证书链。
func (a *API) exportBundle(w http.ResponseWriter, r *http.Request) {
	c, ok := a.m.ByID(r.PathValue("id"))
	if !ok {
		api.WriteErr(w, http.StatusNotFound, "证书不存在")
		return
	}
	chain, err := a.m.ReadChain(c)
	if err != nil {
		api.WriteErr(w, http.StatusNotFound, "证书文件不可读：%v", err)
		return
	}
	key, err := a.m.ReadKey(c)
	if err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	// 先在内存里打完包再写响应：中途出错还能返回 JSON 错误，不会吐出半个 ZIP。
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	now := time.Now()
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"fullchain.pem", chain, 0o644},
		{"privkey.pem", key, 0o600},
		{"README.txt", []byte(exportReadme(c, now)), 0o644},
	} {
		hdr := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: now}
		hdr.SetMode(f.mode)
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			api.WriteErr(w, http.StatusInternalServerError, "打包失败：%v", err)
			return
		}
		if _, err := fw.Write(f.data); err != nil {
			api.WriteErr(w, http.StatusInternalServerError, "打包失败：%v", err)
			return
		}
	}
	if err := zw.Close(); err != nil {
		api.WriteErr(w, http.StatusInternalServerError, "打包失败：%v", err)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, exportName(c)))
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())

	// 导出私钥是敏感动作，留一条可追溯的日志。
	a.m.Bus().Publish("cert", "warn", "已导出证书「%s」的私钥（ZIP 包），用完请删除本地副本", c.Name)
}

// exportName 生成纯 ASCII 的压缩包文件名（Content-Disposition 不接受中文回退）。
func exportName(c core.Certificate) string {
	name := strings.ToLower(strings.TrimSpace(c.PrimaryDomain))
	if name == "" {
		name = "certificate"
	}
	name = strings.TrimPrefix(name, "*.")
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "certificate"
	}
	return out
}

func exportReadme(c core.Certificate, now time.Time) string {
	var sb strings.Builder
	sb.WriteString("fnGate 证书导出包\n")
	sb.WriteString("==================\n\n")
	fmt.Fprintf(&sb, "名称：%s\n主域名：%s\n签发者：%s\n有效期：%s ~ %s\nSHA-256 指纹：%s\n导出时间：%s\n\n",
		c.Name, c.PrimaryDomain, c.Issuer, fmtCertTime(c.NotBefore), fmtCertTime(c.NotAfter), c.Fingerprint, now.Format("2006-01-02 15:04:05"))
	sb.WriteString("包含文件\n")
	sb.WriteString("  fullchain.pem  证书链（叶子证书 + 中间证书），导入时选这个\n")
	sb.WriteString("  privkey.pem    私钥（未加密，权限 0600）\n\n")
	sb.WriteString("导入飞牛系统证书\n")
	sb.WriteString("  1. 飞牛桌面 → 系统设置 → 网络 → 证书\n")
	sb.WriteString("  2. 选择「添加证书 / 导入」，证书选 fullchain.pem，私钥选 privkey.pem\n")
	sb.WriteString("  3. 保存后到 HTTPS 服务设置里选用这张证书\n\n")
	sb.WriteString("注意\n")
	sb.WriteString("  · privkey.pem 等同于该域名的身份，任何人拿到都能冒充它 —— 导入完成后请删除本地副本\n")
	sb.WriteString("  · 本包由 fnGate 导出，证书续期后需要重新导出并重新导入\n")
	return sb.String()
}

// fmtCertTime 把库里存的 RFC3339 时间显示成本地可读格式，解析失败就原样回显。
func fmtCertTime(s string) string {
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s)); err == nil {
		return t.Local().Format("2006-01-02 15:04")
	}
	return s
}

type updatePayload struct {
	Name      string `json:"name"`
	AutoRenew *bool  `json:"auto_renew"`
}

func (a *API) update(w http.ResponseWriter, r *http.Request) {	id := r.PathValue("id")
	var p updatePayload
	if err := api.DecodeJSON(r, &p); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if strings.TrimSpace(p.Name) != "" {
		if err := a.m.Rename(id, p.Name); err != nil {
			api.WriteErr(w, http.StatusBadRequest, "%v", err)
			return
		}
	}
	if p.AutoRenew != nil {
		if err := a.m.SetAutoRenew(id, *p.AutoRenew); err != nil {
			api.WriteErr(w, http.StatusBadRequest, "%v", err)
			return
		}
	}
	api.WriteOK(w, map[string]bool{"updated": true})
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) {
	if err := a.m.Delete(r.PathValue("id")); err != nil {
		api.WriteErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	api.WriteOK(w, map[string]bool{"deleted": true})
}
