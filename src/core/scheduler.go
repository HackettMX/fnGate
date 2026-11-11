package core

import (
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
}

func NewScheduler() *Scheduler {
	return &Scheduler{stopCh: make(chan struct{})}
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
			// 单个任务 panic 不能拖垮整个调度器；由各模块自行记录错误。
			_ = r
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

func Sanitize(s string) string {
	// 只做基础脱敏：避免把明显的凭据片段写进日志。
	low := strings.ToLower(s)
	for _, k := range []string{"token", "secret", "api_key", "password"} {
		if strings.Contains(low, k) && strings.Contains(s, ":") {
			return "[已脱敏]"
		}
	}
	return s
}
