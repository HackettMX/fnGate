package core

import (
	"fmt"
	"sync"
	"time"
)

type Event struct {
	ID      int64  `json:"id"`
	Time    string `json:"time"`
	Module  string `json:"module"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// EventBus 保存最近若干条事件供界面轮询，并支持内部订阅。
type EventBus struct {
	mu     sync.RWMutex
	events []Event
	seq    int64
	subs   map[int64]chan Event
	nextID int64
}

func NewEventBus() *EventBus {
	return &EventBus{events: make([]Event, 0, 256), subs: map[int64]chan Event{}}
}

func (b *EventBus) Publish(module, level, format string, args ...interface{}) {
	e := Event{Time: time.Now().Format("2006-01-02 15:04:05"), Module: module, Level: level, Message: fmt.Sprintf(format, args...)}
	b.mu.Lock()
	b.seq++
	e.ID = b.seq
	b.events = append(b.events, e)
	if len(b.events) > 300 {
		b.events = append([]Event(nil), b.events[len(b.events)-300:]...)
	}
	targets := make([]chan Event, 0, len(b.subs))
	for _, ch := range b.subs {
		targets = append(targets, ch)
	}
	b.mu.Unlock()
	for _, ch := range targets {
		select {
		case ch <- e:
		default:
		}
	}
}

// Since 返回 id 大于 after 的事件，最多 200 条。
func (b *EventBus) Since(after int64) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Event, 0, len(b.events))
	for _, e := range b.events {
		if e.ID > after {
			out = append(out, e)
		}
	}
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

func (b *EventBus) Recent(n int) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if n <= 0 || n > len(b.events) {
		n = len(b.events)
	}
	out := make([]Event, n)
	copy(out, b.events[len(b.events)-n:])
	return out
}

func (b *EventBus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.subs[id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
		close(ch)
	}
}
