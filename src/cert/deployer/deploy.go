package deployer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Deploy 执行完整部署事务。成功返回验证结果；失败自动回滚并验证旧证书 HTTPS。
func (e *Engine) Deploy(input PrepareInput, running bool) (*DeployResult, error) {
	mu.Lock()
	if running || e.busy {
		mu.Unlock()
		return nil, fail(CodeBusy)
	}
	e.busy = true
	mu.Unlock()
	defer func() {
		mu.Lock()
		e.busy = false
		mu.Unlock()
	}()

	j, _, _, err := e.plan(input)
	if err != nil {
		return nil, err
	}
	if input.PlanID == "" || input.PlanID != j.PlanID {
		return nil, fail(CodeConflict)
	}
	if err := e.ensureStateDir(); err != nil {
		return nil, err
	}
	active := e.journalPath()
	if _, err := os.Lstat(active); err == nil {
		return nil, fail(CodeRecovery)
	}

	// 1. 持久记录事务后再做任何修改。此时尚未产生副作用，失败直接返回。
	if err := e.writeJournal(j); err != nil {
		return nil, err
	}
	stage := StageMetadata

	// 2. 二次校验所有文件与网关未变化。
	if err := e.verifyPristine(j); err != nil {
		return e.rollbackWithFailure(j, stage, err)
	}

	// 3. CAS 更新数据库行。
	if err := compareAndSwapRow(j.RowBefore, j.RowAfter); err != nil {
		return e.rollbackWithFailure(j, stage, err)
	}

	// 4. 原子写所有证书/索引文件。
	stage = StageFiles
	for _, f := range j.Files {
		mode := os.FileMode(f.Mode)
		if f.NextMode != 0 {
			mode = f.NextMode
		}
		gid := f.GID
		if f.NextGID > 0 {
			gid = f.NextGID
		}
		if err := e.replace(f, mustB64(f.Next), mode, gid); err != nil {
			return e.rollbackWithFailure(j, stage, err)
		}
	}

	// 5. 重启系统服务。
	stage = StageRestart
	if err := restartServices(); err != nil {
		return e.rollbackWithFailure(j, stage, err)
	}

	// 6. 用新证书指纹 + 公共信任验证本机 HTTPS。
	stage = StageVerify
	if err := probeTLS(j.ProbeHost, j.ProbePort, j.NewFingerprint, true); err != nil {
		return e.rollbackWithFailure(j, stage, err)
	}

	// 7. 一致性检查：文件、数据库行、网关全部符合预期。
	stage = StageConsistency
	if err := e.verifyConsistency(j); err != nil {
		return e.rollbackWithFailure(j, stage, err)
	}

	// 8. 提交：标记 committed 并把 journal 转为备份。
	j.Committed = true
	if err := e.writeJournal(j); err != nil {
		return nil, fail(CodeRecovery)
	}
	_ = os.Rename(active, filepath.Join(e.StateDir, "backup-"+newUUID()+".json"))
	e.pruneBackups()

	return &DeployResult{
		OK: true, Fingerprint: j.NewFingerprint, ValidTo: j.ValidTo,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// verifyPristine 确认当前文件与网关仍等于 plan 时的原始快照。
func (e *Engine) verifyPristine(j *journal) error {
	for _, f := range j.Files {
		cur, err := e.snapshot(f.File, f.IsCert)
		if err != nil || !sameContent(f.File, cur.Content, f.Content) {
			return fail(CodeConflict)
		}
	}
	cur, err := e.snapshot(e.GatewayPath, false)
	if err != nil || !sameContent(e.GatewayPath, cur.Content, j.Gateway.Content) {
		return fail(CodeConflict)
	}
	return nil
}

// verifyConsistency 确认部署后文件、数据库、网关全部符合新状态。
func (e *Engine) verifyConsistency(j *journal) error {
	for _, f := range j.Files {
		cur, err := e.snapshot(f.File, f.IsCert)
		if err != nil || !sameContent(f.File, cur.Content, f.Next) {
			return fail(CodeConflict)
		}
	}
	rowsRaw, err := psql("SELECT coalesce(json_agg(row_to_json(c) ORDER BY c.id),'[]'::json)::text FROM public.cert c;")
	if err != nil {
		return fail(CodeConflict)
	}
	dec := json.NewDecoder(strings.NewReader(rowsRaw))
	dec.UseNumber()
	var rows []certRow
	if dec.Decode(&rows) != nil {
		return fail(CodeConflict)
	}
	found := false
	for _, r := range rows {
		if rowString(r, "id") == rowString(j.RowAfter, "id") {
			found = equalJSON(canonicalMap(r), canonicalMap(j.RowAfter))
			break
		}
	}
	if !found {
		return fail(CodeConflict)
	}
	cur, err := e.snapshot(e.GatewayPath, false)
	if err != nil || !sameContent(e.GatewayPath, cur.Content, j.Gateway.Content) {
		return fail(CodeConflict)
	}
	return nil
}

func canonicalMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// rollbackWithFailure 记录失败阶段，尝试回滚，成功返回 ROLLED_BACK，失败返回 RECOVERY。
func (e *Engine) rollbackWithFailure(j *journal, stage string, cause error) (*DeployResult, error) {
	j.Failure = &journalFailure{
		Stage: stage, Code: string(codeOf(cause)), At: time.Now().UTC().Format(time.RFC3339),
	}
	_ = e.writeJournal(j)
	if err := e.rollback(j); err != nil {
		return nil, fail(CodeRecovery)
	}
	_ = os.Rename(e.journalPath(), filepath.Join(e.StateDir, "rolled-back-"+newUUID()+".json"))
	// 回滚成功也把失败原因透出，否则用户在界面上只看到「已恢复原证书」而不知道为何失败。
	if d := detailOf(cause); d != "" {
		return nil, failDetail(CodeRolledBack, stage, d)
	}
	return nil, failStage(CodeRolledBack, stage)
}

// rollback 把数据库、文件、服务、旧证书 HTTPS 全部恢复到 before 状态。
func (e *Engine) rollback(j *journal) error {
	rowsRaw, err := psql("SELECT coalesce(json_agg(row_to_json(c) ORDER BY c.id),'[]'::json)::text FROM public.cert c;")
	if err != nil {
		return fail(CodeRecovery)
	}
	dec := json.NewDecoder(strings.NewReader(rowsRaw))
	dec.UseNumber()
	var rows []certRow
	if dec.Decode(&rows) != nil {
		return fail(CodeRecovery)
	}
	var current certRow
	for _, r := range rows {
		if rowString(r, "id") == rowString(j.RowBefore, "id") {
			current = r
			break
		}
	}
	if current == nil || (!equalJSON(current, j.RowBefore) && !equalJSON(current, j.RowAfter)) {
		return fail(CodeRecovery)
	}
	// 文件当前值只能是 before 或 after。
	for _, f := range j.Files {
		cur, err := e.snapshot(f.File, f.IsCert)
		if err != nil || (!sameContent(f.File, cur.Content, f.Content) && !sameContent(f.File, cur.Content, f.Next)) {
			return fail(CodeRecovery)
		}
	}
	curGW, err := e.snapshot(e.GatewayPath, false)
	if err != nil || !sameContent(e.GatewayPath, curGW.Content, j.Gateway.Content) {
		return fail(CodeRecovery)
	}

	if !equalJSON(current, j.RowBefore) {
		if err := compareAndSwapRow(j.RowAfter, j.RowBefore); err != nil {
			return fail(CodeRecovery)
		}
	}
	for _, f := range j.Files {
		if err := e.replace(f, mustB64(f.Content), os.FileMode(f.Mode), f.GID); err != nil {
			return fail(CodeRecovery)
		}
	}
	if err := restartServices(); err != nil {
		return fail(CodeRecovery)
	}
	if err := probeTLS(j.ProbeHost, j.ProbePort, j.OldFingerprint, false); err != nil {
		return fail(CodeRecovery)
	}
	return nil
}

// writeJournal 原子写 active.json（权限 0600）。
func (e *Engine) writeJournal(j *journal) error {
	raw, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fail(CodeRecovery)
	}
	return e.atomic(e.journalPath(), append(raw, '\n'), 0o600, 0, 0)
}

// Recover 启动时从 active.json 恢复：未提交则回滚，已提交则归档。
func (e *Engine) Recover() error {
	if err := e.ensureStateDir(); err != nil {
		e.recoveryFailed = true
		return err
	}
	raw, err := os.ReadFile(e.journalPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		e.recoveryFailed = true
		return fail(CodeRecovery)
	}
	var j journal
	if json.Unmarshal(raw, &j) != nil {
		e.recoveryFailed = true
		return fail(CodeRecovery)
	}
	if !j.Committed {
		if err := e.rollback(&j); err != nil {
			e.recoveryFailed = true
			return fail(CodeRecovery)
		}
	}
	_ = os.Rename(e.journalPath(), filepath.Join(e.StateDir, "recovered-"+newUUID()+".json"))
	e.pruneBackups()
	return nil
}

type backupFile struct {
	name string
	mod  time.Time
}

func (e *Engine) pruneBackups() {
	entries, err := os.ReadDir(e.StateDir)
	if err != nil {
		return
	}
	list := []backupFile{}
	for _, en := range entries {
		n := en.Name()
		if strings.HasPrefix(n, "backup-") || strings.HasPrefix(n, "rolled-back-") || strings.HasPrefix(n, "recovered-") {
			if info, err := en.Info(); err == nil {
				list = append(list, backupFile{n, info.ModTime()})
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].mod.After(list[j].mod) })
	for _, x := range list[10:] {
		_ = os.Remove(filepath.Join(e.StateDir, x.name))
	}
}
