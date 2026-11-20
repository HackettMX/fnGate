package deployer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
func (e *Engine) target(row certRow, st *state) (*targetInfo, error) {
	source, _ := row["source"].(string)
	if source != "upload" {
		return nil, fail(CodeProtected)
	}
	id, _ := row["id"].(json.Number)
	if id == "" {
		return nil, fail(CodeIncompatible)
	}
	certPath, _ := row["certificate"].(string)
	keyPath, _ := row["private_key"].(string)
	if certPath == "" || keyPath == "" {
		return nil, fail(CodeIncompatible)
	}
	certSnap, err := e.snapshot(certPath, true)
	if err != nil {
		return nil, err
	}
	keySnap, err := e.snapshot(keyPath, true)
	if err != nil {
		return nil, err
	}
	parsed, err := inspectCertificate(mustB64(certSnap.Content), mustB64(keySnap.Content), true)
	if err != nil {
		return nil, err
	}

	names := cleanDomains(splitDomains(rowString(row, "san", "domain")))
	if !equalJSON(names, parsed.Domains) ||
		!numEqual(row["valid_from"], parsed.ValidFromMS) ||
		!numEqual(row["valid_to"], parsed.ValidToMS) {
		return nil, fail(CodeIncompatible)
	}

	matches := []int{}
	for i, ent := range st.Entries {
		if ent.Certificate == row["certificate"] && ent.PrivateKey == row["private_key"] {
			matches = append(matches, i)
		}
	}
	if len(matches) != 1 {
		return nil, fail(CodeIncompatible)
	}
	ent := st.Entries[matches[0]]
	if !numEqual(ent.ValidFrom, parsed.ValidFromMS) || !numEqual(ent.ValidTo, parsed.ValidToMS) {
		return nil, fail(CodeIncompatible)
	}

	return &targetInfo{
		Row: row, RowID: id.String(), Cert: certSnap, Key: keySnap,
		Parsed: parsed, Entry: &ent, EntryIndex: matches[0],
	}, nil
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
		if v, ok := row[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func splitDomains(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
}

func numEqual(v interface{}, n int64) bool {
	switch x := v.(type) {
	case json.Number:
		i, err := x.Int64()
		return err == nil && i == n
	case float64:
		return int64(x) == n
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

// Status 列出所有可部署目标。
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

	for _, row := range st.Rows {
		t, err := e.target(row, st)
		if err != nil {
			domains := cleanDomains(splitDomains(rowString(row, "san", "domain")))
			unavailable = append(unavailable, Target{
				ID:      rowString(row, "id"),
				Domains: domains,
				Reason:  Text(codeOf(err)),
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
			if m.Cert == t.Row["certificate"] && m.Key == t.Row["private_key"] {
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
