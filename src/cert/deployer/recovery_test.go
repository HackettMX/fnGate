package deployer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 恢复失败时，预检与部署都必须被拦住，并说明「点修复」而不是只给一个错误码。
func TestRecoveryGuardBlocksDeploy(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{StateDir: dir, Secure: false}
	e.setRecovery(failDetail(CodeRecovery, "rollback", "证书行在回滚时已被改写"))

	for name, err := range map[string]error{
		"prepare": func() error { _, err := e.Prepare(PrepareInput{}, false); return err }(),
		"deploy":  func() error { _, err := e.Deploy(PrepareInput{}, false); return err }(),
	} {
		if codeOf(err) != CodeRecovery {
			t.Fatalf("%s 应返回 RECOVERY，实际 %v", name, err)
		}
		if d := detailOf(err); !strings.Contains(d, "修复") || !strings.Contains(d, "证书行在回滚时已被改写") {
			t.Fatalf("%s 的提示没有给出处置办法或原因：%q", name, d)
		}
	}
}

// 没有残留记录时，修复是幂等的：直接报告可用，不产生副作用。
func TestRepairWithoutJournal(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{StateDir: dir, Secure: false}
	res, err := e.Repair()
	if err != nil {
		t.Fatalf("无残留时修复不应失败：%v", err)
	}
	if !res.Repaired || !strings.Contains(res.Message, "可用") {
		t.Fatalf("修复结果说明不清：%+v", res)
	}
	if failed, _ := e.recoveryState(); failed {
		t.Fatal("修复后不应仍处于恢复失败状态")
	}
}

// 无法回滚的记录会被归档而不是让守护永远起不来；归档文件保留在状态目录。
func TestRepairArchivesBrokenJournal(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{StateDir: dir, Secure: false}
	if err := os.WriteFile(filepath.Join(dir, "active.json"), []byte("{ 这不是 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(); err == nil {
		t.Fatal("损坏的记录应导致恢复失败")
	}
	if failed, msg := e.recoveryState(); !failed || !strings.Contains(msg, "损坏") {
		t.Fatalf("恢复状态应带原因：%v %q", failed, msg)
	}

	res, err := e.Repair()
	if err != nil {
		t.Fatalf("修复失败：%v", err)
	}
	if !res.Repaired {
		t.Fatalf("应报告已修复：%+v", res)
	}
	if _, err := os.Lstat(filepath.Join(dir, "active.json")); !os.IsNotExist(err) {
		t.Fatal("残留记录应被移走")
	}
	entries, _ := os.ReadDir(dir)
	found := false
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), "abandoned-") {
			found = true
		}
	}
	if !found {
		t.Fatal("应保留一份 archived 记录以便回溯")
	}
	if failed, _ := e.recoveryState(); failed {
		t.Fatal("归档后应清除恢复失败标记，否则功能永久不可用")
	}
}

// 备份不足 10 份时清理函数不能越界 panic：守护在启动恢复后会调用它，
// 一旦 panic 就是「进程直接退出 → 部署服务未连接」。
func TestPruneBackupsFewEntries(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{StateDir: dir, Secure: false}
	f := filepath.Join(dir, "recovered-1.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.pruneBackups() // 不得 panic
	if _, err := os.Lstat(f); err != nil {
		t.Fatal("不足 10 份时不应删除任何备份")
	}
}

// 超过 10 份时只保留最新的 10 份。
func TestPruneBackupsKeepsTen(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{StateDir: dir, Secure: false}
	for i := 0; i < 14; i++ {
		name := filepath.Join(dir, "backup-"+string(rune('a'+i))+".json")
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		// 用 mtime 明确新旧顺序（文件系统精度可能不足）。
		ts := time.Now().Add(-time.Duration(14-i) * time.Minute)
		if err := os.Chtimes(name, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	e.pruneBackups()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 10 {
		t.Fatalf("应保留 10 份，实际 %d", len(entries))
	}
}
