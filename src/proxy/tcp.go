package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout = 3 * time.Second
	// 服务端先说话的协议（SSH / SMTP）客户端不会先发数据，首包探测必须有上限。
	peekTimeout = 2 * time.Second
)

type connSet struct {
	mu    sync.Mutex
	items map[net.Conn]struct{}
}

func newConnSet() *connSet { return &connSet{items: map[net.Conn]struct{}{}} }

func (s *connSet) Add(c net.Conn) {
	s.mu.Lock()
	s.items[c] = struct{}{}
	s.mu.Unlock()
}

func (s *connSet) Remove(c net.Conn) {
	s.mu.Lock()
	delete(s.items, c)
	s.mu.Unlock()
}

func (s *connSet) CloseAll() {
	s.mu.Lock()
	list := make([]net.Conn, 0, len(s.items))
	for c := range s.items {
		list = append(list, c)
	}
	s.items = map[net.Conn]struct{}{}
	s.mu.Unlock()
	for _, c := range list {
		_ = c.Close()
	}
}

func (m *Manager) acceptTCP(listenerID string, ln net.Listener, conns *connSet) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conns.Add(c)
		go func(conn net.Conn) {
			defer conns.Remove(conn)
			m.handleTCPConn(listenerID, conn)
		}(c)
	}
}

func (m *Manager) handleTCPConn(listenerID string, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	first, err := br.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})

	var sni string
	var hello []byte
	if err == nil && first[0] == 0x16 {
		hello, err = readClientHello(br)
		if err == nil {
			sni = parseSNI(hello)
		}
	}

	view, ok := m.view.Load().(*runtimeView)
	if !ok {
		return
	}
	routes := view.routes[listenerID]
	r, matched := pickTCPRoute(routes, sni)
	if !matched {
		m.log.Warn("tcp 连接未匹配到路由（入口 %s，sni=%q，路由数 %d）", listenerID, sni, len(routes))
		m.tcpAccess(listenerID, sni, "-", false)
		return
	}
	backend := NormalizeHostPort(r.Backend)
	up, err := net.DialTimeout("tcp", backend, dialTimeout)
	if err != nil {
		m.log.Warn("tcp 后端 %s 不可达: %v", backend, err)
		m.tcpAccess(listenerID, sni, backend, false)
		return
	}
	defer up.Close()
	m.tcpAccess(listenerID, sni, backend, true)

	if len(hello) > 0 {
		if _, err := up.Write(hello); err != nil {
			return
		}
	}
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(conn, up)
}

func (m *Manager) tcpAccess(listenerID, sni, backend string, ok bool) {
	if !m.accessEnabled.Load() {
		return
	}
	state := "ok"
	if !ok {
		state = "failed"
	}
	line := fmt.Sprintf("%s tcp %s sni=%s -> %s %s", time.Now().Format("15:04:05"), listenerID, sni, backend, state)
	m.accessMu.Lock()
	m.accessLines = append(m.accessLines, line)
	if len(m.accessLines) > 300 {
		m.accessLines = append([]string(nil), m.accessLines[len(m.accessLines)-300:]...)
	}
	m.accessMu.Unlock()
	m.log.Info("access %s", line)
}

func readClientHello(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x16 {
		return nil, io.ErrUnexpectedEOF
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length <= 0 || length > 65535 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// parseSNI 从 ClientHello 中提取 server_name 扩展（不终止 TLS，仅用于分流）。
func parseSNI(data []byte) string {
	off := 5 + 4
	if len(data) < off+2 {
		return ""
	}
	off += 2 + 32 // version + random
	if len(data) < off+1 {
		return ""
	}
	sidLen := int(data[off])
	off++
	off += sidLen
	if len(data) < off+2 {
		return ""
	}
	csLen := int(data[off])<<8 | int(data[off+1])
	off += 2 + csLen
	if len(data) < off+1 {
		return ""
	}
	compLen := int(data[off])
	off++
	off += compLen
	if len(data) < off+2 {
		return ""
	}
	extLen := int(data[off])<<8 | int(data[off+1])
	off += 2
	end := off + extLen
	if end > len(data) {
		end = len(data)
	}
	for off+4 <= end {
		etype := int(data[off])<<8 | int(data[off+1])
		elen := int(data[off+2])<<8 | int(data[off+3])
		off += 4
		if etype == 0x00 {
			if off+5 > len(data) {
				return ""
			}
			off += 2 // server_name_list length
			nameType := data[off]
			off++
			nameLen := int(data[off])<<8 | int(data[off+1])
			off += 2
			if nameType == 0 && off+nameLen <= len(data) {
				return strings.ToLower(string(data[off : off+nameLen]))
			}
			return ""
		}
		off += elen
	}
	return ""
}
