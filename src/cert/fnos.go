package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"fngate/core"
)

// 飞牛系统证书索引的可能位置。不同 fnOS 版本路径略有差异，逐个探测。
func DefaultConfPaths() []string {
	return []string{
		"/usr/trim/etc/network_cert_all.conf",
		"/usr/trim/etc/network_gateway_cert.conf",
		"/usr/trim/var/network_cert_all.conf",
		"/etc/trim/network_cert_all.conf",
	}
}

func DefaultSSLRoots() []string {
	return []string{
		"/usr/trim/var/trim_connect/ssls",
		"/usr/trim/etc/ssl/certs",
	}
}

func DefaultAllowedRoots() []string {
	return []string{"/usr/trim", "/etc/trim", "/var/apps"}
}

const snapshotFile = "fnos_index.json"

// SyncOptions 只包含启动期固定的白名单路径；API 不接受任何路径参数。
type SyncOptions struct {
	DataDir, CertsDir, SecretsDir string
	ConfPaths                     []string
	SSLRoots                      []string
	AllowedRoots                  []string
	ChownUser                     string
}

type SyncResult struct {
	Found    int      `json:"found"`
	Written  int      `json:"written"`
	Skipped  int      `json:"skipped"`
	Sources  []string `json:"sources"`
	Warnings []string `json:"warnings"`
	SyncedAt string   `json:"synced_at"`
	Mode     string   `json:"mode"`
}

type snapshotEntry struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	SourceCert string `json:"source_cert,omitempty"`
	SourceKey  string `json:"source_key,omitempty"`
}

type snapshotIndex struct {
	Version  int             `json:"version"`
	SyncedAt string          `json:"synced_at"`
	Entries  []snapshotEntry `json:"entries"`
}

type sysEntry struct {
	Host    string
	CertRef string
	KeyRef  string
	BaseDir string
}

// SyncSystem 是给 root 侧 helper（fngate --cert-sync）调用的纯函数：
// 读取白名单内的飞牛证书索引，把证书对复制成应用私有快照，绝不回写系统证书库。
func SyncSystem(o SyncOptions) (*SyncResult, error) {
	if o.DataDir == "" || o.CertsDir == "" || o.SecretsDir == "" {
		return nil, fmt.Errorf("数据目录未配置")
	}
	res := &SyncResult{Sources: []string{}, Warnings: []string{}, SyncedAt: nowText(), Mode: "live"}
	entries := make([]sysEntry, 0)

	confPaths := uniquePaths(o.ConfPaths)
	for _, p := range confPaths {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			continue
		}
		parsed, err := parseConf(p)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s 解析失败：%v", filepath.Base(p), err))
			continue
		}
		if len(parsed) > 0 {
			res.Sources = append(res.Sources, p)
		}
		entries = append(entries, parsed...)
	}

	// 索引里只有域名时，去证书实体目录补齐证书/私钥。
	needScan := false
	for _, e := range entries {
		if e.CertRef == "" || e.KeyRef == "" {
			needScan = true
			break
		}
	}
	if len(entries) == 0 || needScan {
		for _, root := range uniquePaths(o.SSLRoots) {
			if st, err := os.Stat(root); err != nil || !st.IsDir() {
				continue
			}
			scanned := scanSSLRoot(root)
			if len(scanned) > 0 {
				res.Sources = append(res.Sources, root)
				entries = mergeEntries(entries, scanned)
			}
		}
	}

	res.Found = len(entries)
	index := snapshotIndex{Version: 1, SyncedAt: res.SyncedAt, Entries: []snapshotEntry{}}
	seenID := map[string]bool{}
	for _, e := range entries {
		certPEM, keyPEM, certSrc, keySrc, err := resolvePair(e, o.AllowedRoots)
		if err != nil {
			res.Skipped++
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s：%v", labelOf(e), err))
			continue
		}
		d, err := Inspect(certPEM, keyPEM)
		if err != nil {
			res.Skipped++
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s：%v", labelOf(e), err))
			continue
		}
		host := normalizeDomain(e.Host)
		if host == "" {
			host = d.PrimaryDomain
		}
		sum := sha256.Sum256([]byte(host + "|" + certSrc))
		id := "fnos-" + hex.EncodeToString(sum[:])[:16]
		if seenID[id] {
			res.Skipped++
			continue
		}
		relCert, relKey, err := writeSnapshotPair(o, id, certPEM, keyPEM)
		if err != nil {
			res.Skipped++
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s：%v", labelOf(e), err))
			continue
		}
		seenID[id] = true
		index.Entries = append(index.Entries, snapshotEntry{
			ID: id, Host: host, CertPath: relCert, KeyPath: relKey,
			SourceCert: certSrc, SourceKey: keySrc,
		})
		res.Written++
	}

	// 即使一张都没找到也要写一份空索引：表示「已同步过，系统里没有可用证书」。
	// 但绝不能用空索引覆盖 root helper 之前写好的有效快照，否则降权进程点一次
	// 「同步」就会把明明存在的飞牛证书全部抹掉。
	indexPath := filepath.Join(o.CertsDir, snapshotFile)
	if res.Written == 0 {
		if old, err := os.ReadFile(indexPath); err == nil {
			var prev snapshotIndex
			if json.Unmarshal(old, &prev) == nil && len(prev.Entries) > 0 {
				res.Warnings = append(res.Warnings, "本次未读取到系统证书，已保留上一次的飞牛证书快照")
				return res, nil
			}
		}
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(indexPath, append(raw, '\n'), 0o644); err != nil {
		return nil, fmt.Errorf("写入飞牛证书快照索引失败：%w", err)
	}
	if o.ChownUser != "" {
		chownTree(o.DataDir, o.ChownUser)
	}
	return res, nil
}

func labelOf(e sysEntry) string {
	if e.Host != "" {
		return e.Host
	}
	if e.CertRef != "" {
		return filepath.Base(e.CertRef)
	}
	return "未知证书"
}

func uniquePaths(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func writeSnapshotPair(o SyncOptions, id string, certPEM, keyPEM []byte) (string, string, error) {
	if strings.TrimSpace(id) == "" || strings.ContainsAny(id, `/\..`) {
		return "", "", fmt.Errorf("非法的证书 ID")
	}
	cp := filepath.Join(o.CertsDir, id, "fullchain.pem")
	kp := filepath.Join(o.SecretsDir, "certs", id, "privkey.pem")
	if err := atomicWrite(cp, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := atomicWrite(kp, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	_ = os.Chmod(filepath.Dir(cp), 0o755)
	_ = os.Chmod(filepath.Dir(kp), 0o700)
	rel := func(p string) (string, error) {
		r, err := filepath.Rel(o.DataDir, p)
		if err != nil {
			return "", err
		}
		r = filepath.ToSlash(r)
		if r == ".." || strings.HasPrefix(r, "../") {
			return "", fmt.Errorf("证书路径超出数据目录")
		}
		return r, nil
	}
	rc, err := rel(cp)
	if err != nil {
		return "", "", err
	}
	rk, err := rel(kp)
	if err != nil {
		return "", "", err
	}
	return rc, rk, nil
}

// ---------- 索引解析：JSON / JSONL / 键值文本三种形态都兼容 ----------

func parseConf(path string) ([]sysEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		raw = raw[:8<<20]
	}
	base := filepath.Dir(path)
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}

	var maps []map[string]interface{}
	var whole interface{}
	if jsonErr := json.Unmarshal([]byte(text), &whole); jsonErr == nil {
		collectMaps(whole, &maps)
	} else {
		// JSONL：每行一个 JSON 对象
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, ","))
			if line == "" || (line[0] != '{' && line[0] != '[') {
				continue
			}
			var v interface{}
			if err := json.Unmarshal([]byte(line), &v); err == nil {
				collectMaps(v, &maps)
			}
		}
		if len(maps) == 0 {
			maps = parseKeyValue(text)
		}
		if len(maps) == 0 {
			return nil, fmt.Errorf("文件格式无法识别（既不是 JSON / JSONL，也不是键值文本）")
		}
	}

	out := make([]sysEntry, 0, len(maps))
	for _, m := range maps {
		e := sysEntry{
			Host:    lookupString(m, "host", "domain", "domain_name", "server_name", "sni", "common_name", "cn", "name"),
			CertRef: lookupString(m, "cert", "crt", "cert_path", "cert_file", "certificate", "cert_pem", "fullchain", "fullchain_pem", "chain"),
			KeyRef:  lookupString(m, "key", "private_key", "privkey", "key_path", "key_file", "key_pem", "privkey_pem"),
			BaseDir: base,
		}
		if e.Host == "" && e.CertRef == "" && e.KeyRef == "" {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func collectMaps(v interface{}, out *[]map[string]interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		*out = append(*out, x)
		for _, child := range x {
			collectMaps(child, out)
		}
	case []interface{}:
		for _, child := range x {
			collectMaps(child, out)
		}
	}
}

func lookupString(m map[string]interface{}, keys ...string) string {
	lower := map[string]interface{}{}
	for k, v := range m {
		lower[strings.ToLower(strings.ReplaceAll(k, "-", "_"))] = v
	}
	for _, k := range keys {
		v, ok := lower[k]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
		if nested, ok := v.(map[string]interface{}); ok {
			for _, nk := range []string{"path", "file", "value", "content", "pem"} {
				if s, ok := nested[nk].(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

func parseKeyValue(text string) []map[string]interface{} {
	var out []map[string]interface{}
	cur := map[string]interface{}{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]interface{}{}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			flush()
			continue
		}
		var k, v string
		if i := strings.IndexByte(line, '='); i > 0 {
			k, v = line[:i], line[i+1:]
		} else if i := strings.IndexByte(line, ':'); i > 0 && !strings.HasPrefix(line, "{") {
			k, v = line[:i], line[i+1:]
		} else {
			continue
		}
		cur[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `",'`)
	}
	flush()
	return out
}

// ---------- 证书实体解析 ----------

func resolvePair(e sysEntry, allowedRoots []string) (certPEM, keyPEM []byte, certSrc, keySrc string, err error) {
	certPEM, certSrc, err = resolveRef(e.CertRef, e.BaseDir, allowedRoots)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("证书：%w", err)
	}
	keyPEM, keySrc, err = resolveRef(e.KeyRef, e.BaseDir, allowedRoots)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("私钥：%w", err)
	}
	return certPEM, keyPEM, certSrc, keySrc, nil
}

func resolveRef(ref, baseDir string, allowedRoots []string) ([]byte, string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, "", fmt.Errorf("索引里没有给出证书或私钥")
	}
	if strings.Contains(ref, "-----BEGIN") {
		return []byte(ref), "inline", nil
	}
	path := ref
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	path = filepath.Clean(path)
	if !pathAllowed(path, allowedRoots) {
		return nil, "", fmt.Errorf("路径不在允许范围内：%s", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("文件不可读：%v", err)
	}
	if st.IsDir() || st.Size() > 1<<20 {
		return nil, "", fmt.Errorf("文件不是普通证书文件或体积异常")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("读取失败：%v", err)
	}
	return data, path, nil
}

func pathAllowed(p string, roots []string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		ra, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if abs == ra || strings.HasPrefix(abs, ra+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func scanSSLRoot(root string) []sysEntry {
	certs := []string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			if rel != "." && strings.Count(rel, string(filepath.Separator)) >= 3 {
				return fs.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		isKey := strings.Contains(name, "key") || strings.Contains(name, "private")
		if isKey {
			return nil
		}
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cer") ||
			name == "fullchain.pem" || name == "cert.pem" || strings.HasSuffix(name, ".pem") {
			certs = append(certs, p)
		}
		return nil
	})
	type candidate struct {
		entry sysEntry
		stamp int64
	}
	byHost := map[string]candidate{}
	for _, cp := range certs {
		kp := findSiblingKey(cp)
		if kp == "" {
			continue
		}
		dir := filepath.Dir(cp)
		host := normalizeDomain(filepath.Base(filepath.Dir(dir)))
		if host == "" || strings.Contains(host, " ") {
			host = normalizeDomain(filepath.Base(dir))
		}
		st, _ := os.Stat(cp)
		var stamp int64
		if st != nil {
			stamp = st.ModTime().UnixNano()
		}
		if old, ok := byHost[host]; ok && old.stamp >= stamp {
			continue
		}
		byHost[host] = candidate{entry: sysEntry{Host: host, CertRef: cp, KeyRef: kp, BaseDir: dir}, stamp: stamp}
	}
	out := make([]sysEntry, 0, len(byHost))
	for _, c := range byHost {
		out = append(out, c.entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func findSiblingKey(certPath string) string {
	dir := filepath.Dir(certPath)
	base := strings.TrimSuffix(filepath.Base(certPath), filepath.Ext(certPath))
	for _, name := range []string{
		base + ".key", "privkey.pem", "private.key", "key.pem", base + ".pem.key",
	} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	// 最后兜底：同目录里唯一一个明显的私钥文件
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if !e.IsDir() && (strings.Contains(n, "key") || strings.Contains(n, "private")) {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

func mergeEntries(primary, extra []sysEntry) []sysEntry {
	out := make([]sysEntry, 0, len(primary)+len(extra))
	byHost := map[string]int{}
	for _, e := range primary {
		h := normalizeDomain(e.Host)
		if h != "" {
			if i, ok := byHost[h]; ok {
				if out[i].CertRef == "" {
					out[i].CertRef = e.CertRef
				}
				if out[i].KeyRef == "" {
					out[i].KeyRef = e.KeyRef
				}
				continue
			}
			byHost[h] = len(out)
		}
		out = append(out, e)
	}
	for _, e := range extra {
		h := normalizeDomain(e.Host)
		if i, ok := byHost[h]; ok {
			if out[i].CertRef == "" {
				out[i].CertRef = e.CertRef
			}
			if out[i].KeyRef == "" {
				out[i].KeyRef = e.KeyRef
			}
			continue
		}
		out = append(out, e)
	}
	return out
}

func chownTree(dataDir, username string) {
	if core.EUID() != 0 || username == "" {
		return
	}
	u, err := user.Lookup(username)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	for _, root := range []string{
		filepath.Join(dataDir, "certs"), filepath.Join(dataDir, "secrets"),
	} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil {
				_ = os.Chown(p, uid, gid)
			}
			return nil
		})
	}
}

// ---------- 应用侧：只读消费快照 ----------

// SnapshotInfo 供界面展示「上次同步时间 / 是否有系统证书」。
func (m *Manager) SnapshotInfo() (string, int) {
	raw, err := os.ReadFile(filepath.Join(m.opt.CertsDir, snapshotFile))
	if err != nil {
		return "", -1
	}
	var idx snapshotIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return "", -1
	}
	return idx.SyncedAt, len(idx.Entries)
}

// ImportFromSnapshot 把 root helper 准备好的私有快照登记进证书库。
// 只更新元数据，不改动快照文件，因此降权后的应用用户也能执行。
func (m *Manager) ImportFromSnapshot() (map[string]interface{}, error) {
	raw, err := os.ReadFile(filepath.Join(m.opt.CertsDir, snapshotFile))
	if err != nil {
		return map[string]interface{}{"imported": 0, "updated": 0, "removed": 0, "note": "尚未生成飞牛证书快照，请先重启应用或以 root 执行 --cert-sync"}, nil
	}
	var idx snapshotIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("飞牛证书快照索引损坏：%w", err)
	}

	added, updated := 0, 0
	liveIDs := map[string]bool{}
	var warnings []string
	for _, e := range idx.Entries {
		cp, err := m.absFromRel(e.CertPath)
		if err != nil {
			warnings = append(warnings, e.Host+": 证书路径非法")
			continue
		}
		kp, err := m.absFromRel(e.KeyPath)
		if err != nil {
			warnings = append(warnings, e.Host+": 私钥路径非法")
			continue
		}
		certPEM, err := os.ReadFile(cp)
		if err != nil {
			warnings = append(warnings, e.Host+": 证书文件不可读")
			continue
		}
		keyPEM, err := os.ReadFile(kp)
		if err != nil {
			warnings = append(warnings, e.Host+": 私钥文件不可读")
			continue
		}
		d, err := Inspect(certPEM, keyPEM)
		if err != nil {
			warnings = append(warnings, e.Host+": "+err.Error())
			continue
		}
		liveIDs[e.ID] = true
		_, exists := m.ByID(e.ID)
		name := "飞牛证书 · " + e.Host
		c := core.Certificate{
			ID: e.ID, Name: name, Source: "fnos",
			PrimaryDomain: d.PrimaryDomain, SANs: d.SANs, Issuer: d.Issuer,
			NotBefore: d.NotBefore, NotAfter: d.NotAfter, Fingerprint: d.Fingerprint,
			CertPath: e.CertPath, KeyPath: e.KeyPath,
			CreatedAt: nowText(), UpdatedAt: nowText(),
		}
		if err := m.opt.Store.Update(func(st *core.State) error {
			for i := range st.Certificates {
				if st.Certificates[i].ID != e.ID {
					continue
				}
				c.CreatedAt = st.Certificates[i].CreatedAt
				// 只读导入不覆盖用户改过的名称。
				if !strings.HasPrefix(st.Certificates[i].Name, "飞牛证书") {
					c.Name = st.Certificates[i].Name
				}
				st.Certificates[i] = c
				return nil
			}
			st.Certificates = append(st.Certificates, c)
			return nil
		}); err != nil {
			warnings = append(warnings, e.Host+": "+err.Error())
			continue
		}
		if exists {
			updated++
		} else {
			added++
		}
		m.Invalidate(e.ID)
	}

	removed := 0
	st := m.opt.Store.Snapshot()
	for _, c := range st.Certificates {
		if c.Source != "fnos" || liveIDs[c.ID] {
			continue
		}
		if len(m.References(c.ID)) > 0 {
			warnings = append(warnings, c.Name+" 已从飞牛系统移除，但仍被反代引用，已保留记录")
			continue
		}
		if err := m.opt.Store.Update(func(s *core.State) error {
			kept := make([]core.Certificate, 0, len(s.Certificates))
			for _, x := range s.Certificates {
				if x.ID != c.ID {
					kept = append(kept, x)
				}
			}
			s.Certificates = kept
			return nil
		}); err == nil {
			m.Invalidate(c.ID)
			removed++
		}
	}
	if added+updated+removed > 0 {
		m.opt.Bus.Publish("cert", "info", "已同步飞牛系统证书：新增 %d、更新 %d、移除 %d", added, updated, removed)
	}
	return map[string]interface{}{
		"imported": added, "updated": updated, "removed": removed,
		"synced_at": idx.SyncedAt, "found": len(idx.Entries), "warnings": warnings,
	}, nil
}

// Sync 是界面「同步飞牛证书」按钮的入口：先尝试直接读取（root 或文件可读时有效），
// 再消费 root helper 生成的快照；两条路都失败时给出可执行的提示，而不是静默成功。
func (m *Manager) Sync() (map[string]interface{}, error) {
	o := SyncOptions{
		DataDir: m.opt.DataDir, CertsDir: m.opt.CertsDir, SecretsDir: m.opt.SecretsDir,
		ConfPaths: m.opt.SysConfPaths, SSLRoots: m.opt.SysSSLRoots,
		AllowedRoots: m.opt.SysAllowedRoots, ChownUser: os.Getenv("FNGATE_APP_USER"),
	}
	live, liveErr := SyncSystem(o)
	imported, err := m.ImportFromSnapshot()
	if err != nil {
		return nil, err
	}
	if live != nil {
		imported["live_written"] = live.Written
		imported["live_found"] = live.Found
		imported["live_sources"] = live.Sources
		imported["live_warnings"] = live.Warnings
		imported["mode"] = "live"
	}
	if liveErr != nil {
		imported["live_error"] = liveErr.Error()
	}
	imported["euid"] = core.EUID()
	if live != nil && live.Written == 0 && len(live.Sources) == 0 {
		imported["note"] = "未探测到飞牛系统证书索引，可能当前不是 fnOS 环境或证书路径已变化；可使用「上传证书」或「ACME 申请」"
	}
	if m.opt.Logger != nil {
		m.opt.Logger.Info("飞牛证书同步完成: %v", imported)
	}
	return imported, nil
}
