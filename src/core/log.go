package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	mu    sync.Mutex
	level int
	file  *os.File
	lines []string
}

var levelMap = map[string]int{"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}

func NewLogger(dir, level string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "fngate.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f, level: levelMap[strings.ToUpper(level)], lines: []string{}}, nil
}

func (l *Logger) SetLevel(level string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if v, ok := levelMap[strings.ToUpper(level)]; ok {
		l.level = v
	}
}

func (l *Logger) log(lvl int, tag, format string, args ...interface{}) {
	msg := Sanitize(fmt.Sprintf(format, args...))
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), tag, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if lvl < l.level {
		return
	}
	l.lines = append(l.lines, line)
	if len(l.lines) > 1000 {
		l.lines = append([]string(nil), l.lines[len(l.lines)-1000:]...)
	}
	if l.file != nil {
		_, _ = l.file.WriteString(line + "\n")
	}
}

func (l *Logger) Debug(f string, a ...interface{}) { l.log(10, "DEBUG", f, a...) }
func (l *Logger) Info(f string, a ...interface{})  { l.log(20, "INFO", f, a...) }
func (l *Logger) Warn(f string, a ...interface{})  { l.log(30, "WARN", f, a...) }
func (l *Logger) Error(f string, a ...interface{}) { l.log(40, "ERROR", f, a...) }

func (l *Logger) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.lines) {
		n = len(l.lines)
	}
	out := make([]string, n)
	copy(out, l.lines[len(l.lines)-n:])
	return out
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}
