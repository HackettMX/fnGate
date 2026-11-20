package deployer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// certRow 是 PostgreSQL public.cert 的一行（保留全部字段用于 CAS 整行比较）。
// 用 json.Number 保留数字原始表示，避免浮点精度丢失。
type certRow map[string]interface{}

// indexEntry 是 network_cert_all.conf 里的条目。
type indexEntry struct {
	Certificate string      `json:"certificate"`
	PrivateKey  string      `json:"privateKey"`
	Fullchain   string      `json:"fullchain,omitempty"`
	ValidFrom   json.Number `json:"validFrom"`
	ValidTo     json.Number `json:"validTo"`
}

// gatewayMapping 是 network_gateway_cert.conf 里的条目。
type gatewayMapping struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	Host string `json:"host"`
}

// state 是一次 read 的三方状态快照。
type state struct {
	Rows     []certRow
	Entries  []indexEntry
	Mappings []gatewayMapping
	Index    *fileSnapshot
	Gateway  *fileSnapshot
}

// journal 是部署事务的完整记录，落盘于 active.json 供崩溃恢复。
type journal struct {
	Files          []*fileSnapshot `json:"files"`
	RowBefore      certRow         `json:"row_before"`
	RowAfter       certRow         `json:"row_after"`
	Gateway        *fileSnapshot   `json:"gateway"`
	ProbeHost      string          `json:"probe_host"`
	ProbePort      int             `json:"probe_port"`
	OldFingerprint string          `json:"old_fingerprint"`
	NewFingerprint string          `json:"new_fingerprint"`
	ValidTo        string          `json:"valid_to"`
	PlanID         string          `json:"plan_id"`
	Committed      bool            `json:"committed,omitempty"`
	Failure        *journalFailure `json:"failure,omitempty"`
}

type journalFailure struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
	At    string `json:"at"`
}

// mu 保护 busy / recovery 状态，单个部署串行。
var mu sync.Mutex

// read 读取并解析索引、网关映射、数据库行。
func (e *Engine) read() (*state, error) {
	indexSnap, err := e.snapshot(e.IndexPath, false)
	if err != nil {
		return nil, err
	}
	gwSnap, err := e.snapshot(e.GatewayPath, false)
	if err != nil {
		return nil, err
	}
	rowsRaw, err := psql("SELECT coalesce(json_agg(row_to_json(c) ORDER BY c.id),'[]'::json)::text FROM public.cert c;")
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(rowsRaw))
	dec.UseNumber()
	var rows []certRow
	if err := dec.Decode(&rows); err != nil {
		return nil, fail(CodeIncompatible)
	}

	idxDec := json.NewDecoder(strings.NewReader(string(mustB64(indexSnap.Content))))
	idxDec.UseNumber()
	var entries []indexEntry
	if err := idxDec.Decode(&entries); err != nil {
		return nil, fail(CodeIncompatible)
	}

	var mappings []gatewayMapping
	if err := json.Unmarshal(mustB64(gwSnap.Content), &mappings); err != nil {
		return nil, fail(CodeIncompatible)
	}

	if len(rows) > 1024 || len(entries) > 1024 || len(mappings) > 1024 {
		return nil, fail(CodeIncompatible)
	}
	return &state{Rows: rows, Entries: entries, Mappings: mappings, Index: indexSnap, Gateway: gwSnap}, nil
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// target 校验一条数据库证书行是可部署目标（仅 upload 来源），并交叉核对 PEM 与索引。
// 每一步失败都附上脱敏诊断，让真机上的字段差异可直接从界面读出。
func (e *Engine) target(row certRow, st *state) (*targetInfo, error) {
	source := rowText(row["source"])
	if source != "upload" {
		return nil, failDetail(CodeProtected, "source",
			fmt.Sprintf("source=%q（期望 \"upload\"）；该证书可能是系统自带或新版字段值", source))
	}
	id := rowString(row, "id")
	if n, err := strconv.ParseInt(id, 10, 64); err != nil || n <= 0 {
		return nil, failDetail(CodeIncompatible, "id", fmt.Sprintf("id=%q 不是正整数（类型 %s）", id, rowTypeName(row["id"])))
	}
	certPath, keyPath := rowString(row, "certificate"), rowString(row, "private_key")
	if certPath == "" || keyPath == "" {
		return nil, failDetail(CodeIncompatible, "paths",
			fmt.Sprintf("certificate=%q（%s）、private_key=%q（%s），字段名或取值与预期不符",
				certPath, rowTypeName(row["certificate"]), keyPath, rowTypeName(row["private_key"])))
	}
	certSnap, err := e.snapshot(certPath, true)
	if err != nil {
		return nil, failDetail(CodeIncompatible, "cert-file", e.fileFailDetail(certPath, true, err))
	}
	keySnap, err := e.snapshot(keyPath, true)
	if err != nil {
		return nil, failDetail(CodeIncompatible, "key-file", e.fileFailDetail(keyPath, true, err))
	}
	parsed, err := inspectCertificate(mustB64(certSnap.Content), mustB64(keySnap.Content), true)
	if err != nil {
		d := detailOf(err)
		if d == "" {
			d = "证书或私钥内容无法解析"
		}
		return nil, failDetail(CodeInvalid, "pem",
			fmt.Sprintf("certificate=%s（%d 字节），private_key=%s（%d 字节）：%s",
				certPath, len(mustB64(certSnap.Content)), keyPath, len(mustB64(keySnap.Content)), d))
	}

	names := cleanDomains(splitDomains(rowString(row, "san", "domain")))
	if !equalJSON(names, parsed.Domains) {
		return nil, failDetail(CodeIncompatible, "domains",
			fmt.Sprintf("数据库域名 %v 与证书 SAN %v 不一致（san 原始类型 %s）",
				names, parsed.Domains, rowTypeName(row["san"])))
	}
	if !numEqual(row["valid_from"], parsed.ValidFromMS) || !numEqual(row["valid_to"], parsed.ValidToMS) {
		return nil, failDetail(CodeIncompatible, "timestamps",
			fmt.Sprintf("数据库有效期 valid_from=%v（%s）/ valid_to=%v（%s），证书解析为 %d / %d 毫秒；"+
				"若数据库是秒级时间戳则说明 fnOS 版本使用了不同单位",
				rowText(row["valid_from"]), rowTypeName(row["valid_from"]),
				rowText(row["valid_to"]), rowTypeName(row["valid_to"]),
				parsed.ValidFromMS, parsed.ValidToMS))
	}

	matches := []int{}
	for i, ent := range st.Entries {
		if ent.Certificate == rowString(row, "certificate") && ent.PrivateKey == rowString(row, "private_key") {
			matches = append(matches, i)
		}
	}
	if len(matches) != 1 {
		return nil, failDetail(CodeIncompatible, "index",
			fmt.Sprintf("network_cert_all.conf 共 %d 条，与数据库 certificate/privateKey 精确匹配 %d 条（需恰好 1 条）",
				len(st.Entries), len(matches)))
	}
	ent := st.Entries[matches[0]]
	if !numEqual(ent.ValidFrom, parsed.ValidFromMS) || !numEqual(ent.ValidTo, parsed.ValidToMS) {
		return nil, failDetail(CodeIncompatible, "index-timestamps",
			fmt.Sprintf("索引条目 validFrom=%v / validTo=%v，证书解析为 %d / %d 毫秒",
				rowText(ent.ValidFrom), rowText(ent.ValidTo), parsed.ValidFromMS, parsed.ValidToMS))
	}

	return &targetInfo{
		Row: row, RowID: id, Cert: certSnap, Key: keySnap,
		Parsed: parsed, Entry: &ent, EntryIndex: matches[0],
	}, nil
}

// fileFailDetail 生成一处文件不可用原因的完整说明：优先给出逐项检查事实，
// 其次是底层错误里的诊断，最后才回落到通用描述。
func (e *Engine) fileFailDetail(file string, isCert bool, err error) string {
	if rep := e.pathReport(file, isCert); rep != "" {
		return rep
	}
	if d := detailOf(err); d != "" {
		return d
	}
	return fmt.Sprintf("无法读取 %s（需普通文件、位于 %s 下、属主 root 且所在目录不可被其他用户改写）", file, e.CertRoot)
}

type targetInfo struct {
	Row        certRow
	RowID      string
	Cert       *fileSnapshot
	Key        *fileSnapshot
	Parsed     *parsedCert
	Entry      *indexEntry
	EntryIndex int
}

func rowString(row certRow, keys ...string) string {
	for _, k := range keys {
		if s := rowText(row[k]); s != "" {
			return s
		}
	}
	return ""
}

// rowText 把 DB/JSON 里的值转成字符串，对齐参考实现 JS String() 的弱类型行为。
// PostgreSQL row_to_json 的数字是 JSON number（解码为 json.Number），
// san 等字段可能是数组或 "DNS:xxx" 形式；只做标量展开，嵌套对象不展开，
// 避免把整个对象当文件路径使用。
func rowText(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	case []interface{}:
		parts := make([]string, 0, len(x))
		for _, it := range x {
			if s := rowText(it); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

// rowTypeName 只用于诊断，说明字段的实际 JSON 类型，便于真机排障。
func rowTypeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case json.Number, float64, float32, int, int64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

func splitDomains(s string) []string {
	s = strings.TrimSpace(s)
	// 某些 fnOS 版本的 san 存成 JSON 数组字符串。
	if strings.HasPrefix(s, "[") {
		var arr []interface{}
		if json.Unmarshal([]byte(s), &arr) == nil {
			out := make([]string, 0, len(arr))
			for _, it := range arr {
				out = append(out, rowText(it))
			}
			return out
		}
	}
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
}

// numEqual 比较 DB/索引里的时间与证书解析出的毫秒时间戳。
// 兼容 JSON number、浮点、数字字符串；不猜测秒/毫秒（单位差异写入会破坏一致性，
// 只能由诊断信息暴露后按真机情况处理）。
func numEqual(v interface{}, n int64) bool {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i == n
		}
		if f, err := x.Float64(); err == nil {
			return int64(f) == n
		}
	case float64:
		return int64(x) == n
	case float32:
		return int64(x) == n
	case int:
		return int64(x) == n
	case int64:
		return x == n
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return err == nil && i == n
	}
	return false
}

func numValue(v interface{}) json.Number {
	switch x := v.(type) {
	case json.Number:
		return x
	case float64:
		return json.Number(fmt.Sprintf("%.0f", x))
	}
	return json.Number("0")
}

// publicTarget 把内部目标转成前端视图。
func publicTarget(t *targetInfo, bound bool, probeHost string, verified []int) Target {
	return Target{
		ID:            t.RowID,
		Domains:       t.Parsed.Domains,
		ValidTo:       timeFromMS(t.Parsed.ValidToMS),
		Fingerprint:   t.Parsed.Fingerprint,
		Bound:         bound,
		ProbeHost:     probeHost,
		VerifiedPorts: verified,
	}
}

func timeFromMS(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// Status 列出所有可部署目标。任何一行被跳过都带上可读原因，
// 避免真机上出现「0 个目标」却无从排查。
func (e *Engine) Status() (*StatusResult, error) {
	mu.Lock()
	defer mu.Unlock()
	if e.recoveryFailed {
		return nil, fail(CodeRecovery)
	}
	st, err := e.read()
	if err != nil {
		return nil, err
	}
	ports := detectPorts()
	available := []Target{}
	unavailable := []Target{}

	// 全局诊断：只看结构与类型统计，不输出任何证书/私钥内容。
	sourceStat := map[string]int{}
	for _, row := range st.Rows {
		sourceStat[fmt.Sprintf("%q", rowText(row["source"]))]++
	}
	sources := make([]string, 0, len(sourceStat))
	for k, v := range sourceStat {
		sources = append(sources, fmt.Sprintf("%s ×%d", k, v))
	}
	sort.Strings(sources)
	diagnostics := []string{
		fmt.Sprintf("public.cert 共 %d 行；source 分布：%s", len(st.Rows), strings.Join(sources, ", ")),
		fmt.Sprintf("network_cert_all.conf %d 条，network_gateway_cert.conf %d 条；nginx 监听端口 %v（fnOS 默认 HTTPS 为 5667）",
			len(st.Entries), len(st.Mappings), ports),
		fmt.Sprintf("证书根目录 %s", e.CertRoot),
	}

	for _, row := range st.Rows {
		t, err := e.target(row, st)
		if err != nil {
			domains := cleanDomains(splitDomains(rowString(row, "san", "domain")))
			unavailable = append(unavailable, Target{
				ID:      rowString(row, "id"),
				Domains: domains,
				Reason:  Text(codeOf(err)),
				Detail:  detailOf(err),
			})
			continue
		}
		host := ""
		for _, d := range t.Parsed.Domains {
			if !strings.HasPrefix(d, "*.") {
				host = d
				break
			}
		}
		bound := false
		for _, m := range st.Mappings {
			if m.Cert == rowString(t.Row, "certificate") && m.Key == rowString(t.Row, "private_key") {
				bound = true
				break
			}
		}
		verified := []int{}
		if host != "" && bound {
			for _, p := range ports {
				if probeTLS(host, p, t.Parsed.Fingerprint, false) == nil {
					verified = append(verified, p)
				}
			}
		}
		available = append(available, publicTarget(t, bound, host, verified))
	}
	sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	return &StatusResult{
		Available: true, Experimental: true,
		Targets: available, Unavailable: unavailable,
		Skipped: len(unavailable), Running: e.busy,
		Ports: ports, Diagnostics: diagnostics,
	}, nil
}

// stateDir 辅助：确保状态目录为 0700 且属主安全。
func (e *Engine) ensureStateDir() error {
	if err := os.MkdirAll(e.StateDir, 0o700); err != nil {
		return fail(CodeIncompatible)
	}
	st, err := os.Lstat(e.StateDir)
	if err != nil || !st.IsDir() || !ownedByRootNotWritable(st) {
		return fail(CodeIncompatible)
	}
	return nil
}

func (e *Engine) journalPath() string { return filepath.Join(e.StateDir, "active.json") }
