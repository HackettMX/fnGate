package deployer

import (
	"encoding/json"
	"fmt"
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

	// 优先使用预检生成的那份计划：用户确认的就是它。
	// 只有计划已过期/守护重启过时才重新计算，并解释为什么对不上。
	var j *journal
	if cached, ok := prepared.get(input.PlanID); ok {
		j = cached
	} else {
		recomputed, _, _, err := e.plan(input)
		if err != nil {
			return nil, err
		}
		if input.PlanID == "" {
			return nil, failDetail(CodeConflict, "plan",
				"缺少 plan_id：请先预检，再确认同步（预检与部署不能分两次请求）")
		}
		if recomputed.PlanID != input.PlanID {
			return nil, failDetail(CodeConflict, "plan",
				fmt.Sprintf("预检计划已失效（部署服务可能重启过，或系统配置在预检后被改动）；"+
					"当前计划 %s，你确认的计划 %s，请重新预检", shortPlanID(recomputed.PlanID), shortPlanID(input.PlanID)))
		}
		j = recomputed
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

	// 2. 二次校验所有文件与网关未变化。此阶段尚未写任何东西，
	//    失败只丢弃计划、不触发回滚（回滚会把外部改动一并覆盖回去）。
	if err := e.verifyPristine(j); err != nil {
		_ = os.Remove(active)
		return nil, err
	}

	// 3. CAS 更新数据库行。CAS 失败说明该行未被动过，同样无需回滚。
	if err := compareAndSwapRow(j.RowBefore, j.RowAfter); err != nil {
		_ = os.Remove(active)
		return nil, e.metadataConflict(j)
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
	prepared.drop(j.PlanID)

	return &DeployResult{
		OK: true, Fingerprint: j.NewFingerprint, ValidTo: j.ValidTo,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// verifyPristine 确认当前文件与网关仍等于 plan 时的原始快照。
// 任何一处与计划不符都附上具体事实（哪个文件、字节数、权限属主），
// 而不是笼统地说「系统证书或配置已变化」。
func (e *Engine) verifyPristine(j *journal) error {
	for _, f := range j.Files {
		cur, err := e.snapshot(f.File, f.IsCert)
		if err != nil {
			d := detailOf(err)
			if d == "" {
				d = "已不可安全读取"
			}
			return failDetail(CodeConflict, "pristine",
				fmt.Sprintf("%s 在预检之后发生变化：%s", f.File, d))
		}
		if !sameContent(f.File, cur.Content, f.Content) {
			return failDetail(CodeConflict, "pristine",
				fmt.Sprintf("%s 在预检之后被改写（预检 %d 字节 → 现在 %d 字节），已中止以免覆盖其它修改；"+
					"若是刚续期或重新导入过证书，请重新预检", f.File, len(mustB64(f.Content)), len(mustB64(cur.Content))))
		}
		if cur.Mode != f.Mode || cur.UID != f.UID || cur.GID != f.GID {
			return failDetail(CodeConflict, "pristine",
				fmt.Sprintf("%s 的权限/属主在预检之后变化（%04o %d:%d → %04o %d:%d），已中止",
					f.File, f.Mode, f.UID, f.GID, cur.Mode, cur.UID, cur.GID))
		}
	}
	cur, err := e.snapshot(e.GatewayPath, false)
	if err != nil {
		return failDetail(CodeConflict, "pristine", fmt.Sprintf("%s 在预检之后不可读", e.GatewayPath))
	}
	if !sameContent(e.GatewayPath, cur.Content, j.Gateway.Content) {
		return failDetail(CodeConflict, "pristine",
			fmt.Sprintf("%s 在预检之后被改写（%d 字节 → %d 字节），说明飞牛的证书服务配置刚被改动过；"+
				"请重新预检（若刚在飞牛里改过证书绑定，这是预期行为）",
				e.GatewayPath, len(mustB64(j.Gateway.Content)), len(mustB64(cur.Content))))
	}
	return nil
}

// metadataConflict 说明数据库行在预检之后被改了哪些字段（CAS 未命中）。
func (e *Engine) metadataConflict(j *journal) error {
	cur, err := e.currentRow(rowString(j.RowBefore, "id"))
	if err != nil {
		return failDetail(CodeConflict, "metadata",
			fmt.Sprintf("证书行 %s 在预检之后被改动（无法读取当前值：%v），请重新预检", rowString(j.RowBefore, "id"), err))
	}
	changed := []string{}
	for k := range j.RowBefore {
		if canonicalJSON(j.RowBefore[k]) != canonicalJSON(cur[k]) {
			changed = append(changed, fmt.Sprintf("%s：%s → %s", k, trunc(rowText(j.RowBefore[k]), 48), trunc(rowText(cur[k]), 48)))
			if len(changed) >= 4 {
				break
			}
		}
	}
	sort.Strings(changed)
	if len(changed) == 0 {
		return failDetail(CodeConflict, "metadata",
			fmt.Sprintf("证书行 %s 在预检之后被改动（字段值一致，可能是写入时序冲突），请重新预检",
				rowString(j.RowBefore, "id")))
	}
	return failDetail(CodeConflict, "metadata",
		fmt.Sprintf("证书行 %s 在预检之后被改动：%s；请重新预检", rowString(j.RowBefore, "id"), strings.Join(changed, "；")))
}

// currentRow 读取某张证书的当前数据库行。
func (e *Engine) currentRow(id string) (certRow, error) {
	st, err := e.read()
	if err != nil {
		return nil, err
	}
	for _, r := range st.Rows {
		if rowString(r, "id") == id {
			return r, nil
		}
	}
	return nil, fmt.Errorf("行 %s 不存在", id)
}

func shortPlanID(id string) string {
	if len(id) > 10 {
		return id[:10]
	}
	if id == "" {
		return "（空）"
	}
	return id
}

func trunc(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

// verifyConsistency 确认部署后文件、数据库、网关全部符合新状态。
func (e *Engine) verifyConsistency(j *journal) error {
	for _, f := range j.Files {
		cur, err := e.snapshot(f.File, f.IsCert)
		if err != nil || !sameContent(f.File, cur.Content, f.Next) {
			return failDetail(CodeConflict, "consistency",
				fmt.Sprintf("写入后复核失败：%s 的内容与预期不一致", f.File))
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
