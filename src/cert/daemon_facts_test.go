package cert

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 守护不在时，「未就绪」必须带上能定位的事实，而不是一句「未连接」。
func TestDaemonFactsExplainsMissingSocket(t *testing.T) {
	dir := t.TempDir()
	m := New(Options{DataDir: dir, DeployerSocket: filepath.Join(dir, "control.sock")})

	facts := strings.Join(m.daemonFacts(errors.New("dial unix: no such file or directory")), "\n")
	for _, want := range []string{"不存在", "连接结果", "没有 PID 文件", "处理办法"} {
		if !strings.Contains(facts, want) {
			t.Fatalf("诊断缺少 %q：\n%s", want, facts)
		}
	}
}

// PID 文件指向已退出的进程时，要能明确说出「启动后退出」。
func TestDaemonFactsReportsDeadPID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert-deployer.pid"), []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(Options{DataDir: dir, DeployerSocket: filepath.Join(dir, "control.sock")})
	facts := strings.Join(m.daemonFacts(nil), "\n")
	if !strings.Contains(facts, "999999") || !strings.Contains(facts, "已不存在") {
		t.Fatalf("未指出守护进程已退出：\n%s", facts)
	}
}

// 日志里只挑守护相关行，且不能把整段日志倒给用户。
func TestDaemonLogTailFilters(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("2026-11-20 10:00:00 普通业务日志，不该出现\n")
	for i := 0; i < 10; i++ {
		b.WriteString("2026-11-20 10:00:0")
		b.WriteString(string(rune('0' + i)))
		b.WriteString(" cert-deployer started pid=")
		b.WriteString(string(rune('0' + i)))
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "fngate.log"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(Options{DataDir: dir})
	tail := m.daemonLogTail()
	if len(tail) != 6 {
		t.Fatalf("应只保留最近 6 条，实际 %d", len(tail))
	}
	for _, line := range tail {
		if strings.Contains(line, "普通业务日志") {
			t.Fatalf("不应包含无关日志：%s", line)
		}
	}
}

// PID 文件被写成非数字时要当作「没有 PID」，不能拿去拼 /proc 路径。
func TestReadDaemonPIDRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert-deployer.pid"), []byte("12ab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(Options{DataDir: dir})
	if pid := m.readDaemonPID(); pid != "" {
		t.Fatalf("非法 PID 应被忽略，实际 %q", pid)
	}
}
