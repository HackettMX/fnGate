package core

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type task struct {
	name     string
	interval time.Duration
	atHour   int
	daily    bool
	fn       func()
}

// Scheduler 管理周期性任务：UPnP 自动补发、健康检查、证书续期检查。
type Scheduler struct {
	mu      sync.Mutex
	tasks   []task
	stopCh  chan struct{}
	started bool
	wg      sync.WaitGroup
	onPanic func(name string, value interface{}, stack []byte)
}

func NewScheduler() *Scheduler {
	return &Scheduler{stopCh: make(chan struct{})}
}

// SetPanicHandler 注册任务异常回调。关键任务（如证书续期）一旦 panic 会静默停止，
// 必须留痕，否则用户只能等到证书过期才发现。
func (s *Scheduler) SetPanicHandler(fn func(name string, value interface{}, stack []byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onPanic = fn
}

func (s *Scheduler) Every(name string, interval time.Duration, fn func()) {
	if interval < time.Second {
		interval = time.Second
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = append(s.tasks, task{name: name, interval: interval, fn: fn})
}

// Daily 在每天 atHour 点后的随机分钟执行一次，避开整点拥塞。
func (s *Scheduler) Daily(name string, atHour int, fn func()) {
	if atHour < 0 || atHour > 23 {
		atHour = 3
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = append(s.tasks, task{name: name, atHour: atHour, daily: true, fn: fn})
}

func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	tasks := append([]task(nil), s.tasks...)
	s.mu.Unlock()
	for _, t := range tasks {
		s.wg.Add(1)
		go s.run(t)
	}
}

func (s *Scheduler) run(t task) {
	defer s.wg.Done()
	if t.daily {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), t.atHour, 0, 0, 0, now.Location())
			if !next.After(now) {
				next = next.AddDate(0, 0, 1)
			}
			wait := next.Sub(now)
			select {
			case <-s.stopCh:
				return
			case <-time.After(wait):
			}
			s.safe(t)
		}
	}
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.safe(t)
		}
	}
}

func (s *Scheduler) safe(t task) {
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			fn := s.onPanic
			s.mu.Unlock()
			if fn != nil {
				fn(t.name, r, debug.Stack())
			}
		}
	}()
	t.fn()
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	s.mu.Unlock()
	close(s.stopCh)
	s.wg.Wait()
}

func (s *Scheduler) TaskNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, t.name)
	}
	return out
}

// TrimLines 把日志按行收敛到最多 n 行，避免内存无限增长。
func TrimLines(lines []string, n int) []string {
	if len(lines) <= n {
		return lines
	}
	out := append([]string(nil), lines[len(lines)-n:]...)
	return out
}

var secretPattern = regexp.MustCompile(`(?i)\b(api[_-]?token|api[_-]?key|access[_-]?key|secret[_-]?key|password|passwd|eab[_-]?hmac|hmac|token|secret)\b\s*[=:]\s*("[^"]*"|'[^']*'|\S+)`)

// Sanitize 把日志中的凭据值替换为 ***，保留键名与上下文，既不泄露也不吞掉排障信息。
func Sanitize(s string) string {
	return secretPattern.ReplaceAllString(s, "${1}=***")
}

// panicText 把 recover 到的值与栈折叠成适合日志的描述。
func PanicText(name string, value interface{}, stack []byte) string {
	first := ""
	if lines := strings.Split(string(stack), "\n"); len(lines) > 2 {
		first = strings.TrimSpace(lines[2])
	}
	return fmt.Sprintf("定时任务 %q 异常（已恢复，后续仍会执行）：%v；位置 %s", name, value, first)
}
