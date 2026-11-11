package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store 持有一份带版本号的统一状态。所有写操作都经过 Update，
// 采用「克隆草稿 → 校验 → 原子落盘 → 提交内存」的顺序，落盘失败不污染内存。
type Store struct {
	mu         sync.RWMutex
	path       string
	secretsDir string
	data       State
	bus        *EventBus
}

func NewStore(path, secretsDir string, bus *EventBus) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建凭据目录失败: %w", err)
	}
	if bus == nil {
		bus = NewEventBus()
	}
	s := &Store{path: path, secretsDir: secretsDir, bus: bus}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.data = NewState()
		return s.save(s.data)
	}
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		_ = os.WriteFile(s.path+".corrupt", raw, 0o600)
		return fmt.Errorf("配置文件损坏（原文件已备份为 .corrupt）: %w", err)
	}
	old := st.SchemaVersion
	if _, _, err := Migrate(&st); err != nil {
		return err
	}
	if old != CurrentSchema {
		_ = os.WriteFile(fmt.Sprintf("%s.bak-v%d", s.path, old), raw, 0o600)
		if err := s.save(st); err != nil {
			return err
		}
		s.bus.Publish("system", "info", "配置已从 v%d 迁移到 v%d（原文件已备份）", old, CurrentSchema)
	}
	s.data = st
	s.data.Normalize()
	return nil
}

func (s *Store) save(st State) error {
	st.Normalize()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func cloneState(in State) State {
	b, _ := json.Marshal(in)
	var out State
	_ = json.Unmarshal(b, &out)
	out.Normalize()
	return out
}

// Snapshot 返回与内部状态完全隔离的副本。
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.data)
}

// Update 是唯一的写入口。fn 内可自由修改草稿，返回 error 即整体回滚。
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	draft := cloneState(s.data)
	if err := fn(&draft); err != nil {
		return err
	}
	draft.SchemaVersion = CurrentSchema
	if err := s.save(draft); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	s.data = draft
	return nil
}

func (s *Store) SecretsDir() string { return s.secretsDir }
func (s *Store) Bus() *EventBus     { return s.bus }

// SecretPath 把相对名收敛到 secrets 目录内，拒绝路径穿越。
func (s *Store) SecretPath(rel string) (string, error) {
	// 统一成斜杠再判断，兼容 Windows 与 Linux 两种构建环境。
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(rel)))
	if clean == "" || clean == "." || strings.HasPrefix(clean, "/") ||
		strings.Contains(clean, "..") || strings.Contains(clean, ":") {
		return "", fmt.Errorf("非法的凭据路径")
	}
	return filepath.Join(s.secretsDir, filepath.FromSlash(clean)), nil
}

func (s *Store) SecretWrite(rel string, data []byte) error {
	p, err := s.SecretPath(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".secret-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, p)
}

func (s *Store) SecretRead(rel string) ([]byte, error) {
	p, err := s.SecretPath(rel)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (s *Store) SecretDelete(rel string) error {
	p, err := s.SecretPath(rel)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Export 导出不含任何私钥/凭据的配置快照。
func (s *Store) Export(w io.Writer) error {
	st := s.Snapshot()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Import 用外部配置整体替换当前状态（私钥与凭据不导入）。
func (s *Store) Import(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("备份文件不是合法的配置 JSON: %w", err)
	}
	if st.SchemaVersion > CurrentSchema {
		return fmt.Errorf("备份文件版本 v%d 高于当前应用支持的 v%d", st.SchemaVersion, CurrentSchema)
	}
	if _, _, err := Migrate(&st); err != nil {
		return err
	}
	return s.Update(func(cur *State) error {
		*cur = st
		return nil
	})
}
