package core

import (
	"errors"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "state.json"), filepath.Join(dir, "secrets"), NewEventBus())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestStoreUpdateRollback(t *testing.T) {
	s := newTestStore(t)
	err := s.Update(func(st *State) error {
		st.Forwards = append(st.Forwards, Forward{ID: "x"})
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("期望返回错误")
	}
	if got := len(s.Snapshot().Forwards); got != 0 {
		t.Fatalf("落盘失败后内存应回滚，实际 %d 条", got)
	}
	if err := s.Update(func(st *State) error {
		st.Forwards = append(st.Forwards, Forward{ID: "ok", ExternalPort: 443})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Snapshot().Forwards); got != 1 {
		t.Fatalf("期望 1 条，实际 %d", got)
	}
}

func TestMigrateFromOldVersion(t *testing.T) {
	st := State{SchemaVersion: 0}
	from, changed, err := Migrate(&st)
	if err != nil || !changed || from != 0 {
		t.Fatalf("迁移结果异常: from=%d changed=%v err=%v", from, changed, err)
	}
	if st.SchemaVersion != CurrentSchema || st.Settings.ReapplyInterval == 0 || st.Forwards == nil {
		t.Fatal("迁移后默认值未补齐")
	}
	if _, _, err := Migrate(&State{SchemaVersion: CurrentSchema + 1}); err == nil {
		t.Fatal("高版本配置应被拒绝")
	}
}

func TestSecretPathRejectsTraversal(t *testing.T) {
	s := newTestStore(t)
	for _, bad := range []string{"../escape", "/etc/passwd", "..", "a/../../b"} {
		if _, err := s.SecretPath(bad); err == nil {
			t.Fatalf("路径 %q 应被拒绝", bad)
		}
	}
	if err := s.SecretWrite("dns/one.json", []byte(`{"k":"v"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := s.SecretRead("dns/one.json")
	if err != nil || string(got) != `{"k":"v"}` {
		t.Fatalf("凭据读写失败: %q %v", got, err)
	}
}
