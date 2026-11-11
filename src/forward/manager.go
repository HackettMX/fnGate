package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"fngate/core"
)

type MappingView struct {
	core.Forward
	Active bool   `json:"active"`
	Error  string `json:"error,omitempty"`
}

type ExternalMapping struct {
	ExternalPort   int    `json:"external_port"`
	Protocol       string `json:"protocol"`
	InternalPort   int    `json:"internal_port"`
	InternalClient string `json:"internal_client"`
	Description    string `json:"description"`
	Enabled        bool   `json:"enabled"`
}

type Snapshot struct {
	Managed      []MappingView     `json:"managed"`
	External     []ExternalMapping `json:"external"`
	Error        string            `json:"error,omitempty"`
	PausedReason string            `json:"paused_reason,omitempty"`
	LastReapply  string            `json:"last_reapply,omitempty"`
}

type StatusView struct {
	Connected    bool   `json:"connected"`
	ExternalIP   string `json:"external_ip"`
	Gateway      string `json:"gateway"`
	GatewayIP    string `json:"gateway_ip"`
	Error        string `json:"error,omitempty"`
	Managed      int    `json:"managed"`
	Active       int    `json:"active"`
	Missing      int    `json:"missing"`
	PausedReason string `json:"paused_reason,omitempty"`
	LastReapply  string `json:"last_reapply,omitempty"`
}

type AddPayload struct {
	Description    string `json:"description"`
	Protocol       string `json:"protocol"`
	ExternalPort   int    `json:"external_port"`
	InternalPort   int    `json:"internal_port"`
	InternalClient string `json:"internal_client"`
	LeaseTime      int    `json:"lease_time"`
}

// Manager 负责 UPnP 映射的增删查与自动补发。
// 所有对外方法串行执行：路由器 SOAP 接口并发能力弱，串行更稳定。
type Manager struct {
	mu              sync.Mutex
	store           *core.Store
	bus             *core.EventBus
	log             *core.Logger
	igd             *UPnPManager
	lastReapply     time.Time
	lastReapplyText string
	paused          string
}

func New(store *core.Store, bus *core.EventBus, log *core.Logger, sched *core.Scheduler) *Manager {
	m := &Manager{
		store: store, bus: bus, log: log,
		igd: NewUPnPManager(5*time.Second, 300*time.Second),
	}
	sched.Every("forward.reapply", 5*time.Second, m.tick)
	return m
}

func (m *Manager) now() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// enumerate 读取网关状态与路由器映射表，并按需更新网关指纹。
// 调用方必须持有 m.mu。
func (m *Manager) enumerate(st core.State) ([]PortMapping, GatewayStatus, error) {
	ctx := context.Background()
	gw := m.igd.Status(ctx, false)
	if !gw.Connected {
		m.paused = ""
		return nil, gw, errors.New(gw.Error)
	}
	all, err := m.igd.ListMappings(ctx)
	if err != nil {
		// 枚举不可信时绝不补发：缺失可能只是读不到。
		m.paused = "无法读取路由器映射表，已暂停自动补发"
		return nil, gw, err
	}
	if gw.GatewayIP != "" && (st.GatewayFingerprint.IP != gw.GatewayIP || st.GatewayFingerprint.Model != gw.ModelName) {
		changed := st.GatewayFingerprint.IP != "" && st.GatewayFingerprint.IP != gw.GatewayIP
		ip, model := gw.GatewayIP, gw.ModelName
		_ = m.store.Update(func(s *core.State) error {
			s.GatewayFingerprint = core.GatewayFingerprint{IP: ip, Model: model}
			return nil
		})
		if changed {
			m.paused = "检测到网关变化，已暂停自动补发，请确认后手动重新下发"
			m.bus.Publish("forward", "warn", "网关由 %s 变为 %s，自动补发已暂停", st.GatewayFingerprint.IP, ip)
		} else {
			m.paused = ""
		}
	} else {
		m.paused = ""
	}
	return all, gw, nil
}

func sameMapping(f core.Forward, p PortMapping) bool {
	return int(p.ExternalPort) == f.ExternalPort &&
		strings.EqualFold(p.Protocol, f.Protocol) &&
		int(p.InternalPort) == f.InternalPort &&
		(f.InternalClient == "" || p.InternalClient == f.InternalClient)
}

// Mappings 返回本应用托管与路由器上其他设备创建的两个列表。
func (m *Manager) Mappings() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mappingsLocked(true)
}

func (m *Manager) mappingsLocked(withRouter bool) Snapshot {
	st := m.store.Snapshot()
	out := Snapshot{Managed: []MappingView{}, External: []ExternalMapping{}, PausedReason: m.paused, LastReapply: m.lastReapplyText}
	if !withRouter {
		for _, f := range st.Forwards {
			out.Managed = append(out.Managed, MappingView{Forward: f, Active: false, Error: "未检测"})
		}
		return out
	}
	all, _, err := m.enumerate(st)
	if err != nil {
		out.Error = err.Error()
		for _, f := range st.Forwards {
			out.Managed = append(out.Managed, MappingView{Forward: f, Active: false, Error: err.Error()})
		}
		return out
	}
	used := map[string]bool{}
	for _, f := range st.Forwards {
		view := MappingView{Forward: f, Active: false, Error: "路由器上未找到该映射"}
		for _, p := range all {
			if int(p.ExternalPort) == f.ExternalPort && strings.EqualFold(p.Protocol, f.Protocol) {
				used[fmt.Sprintf("%d/%s", p.ExternalPort, strings.ToUpper(p.Protocol))] = true
				if int(p.InternalPort) == f.InternalPort && (f.InternalClient == "" || p.InternalClient == f.InternalClient) && p.Enabled {
					view.Active = true
					view.Error = ""
				} else {
					view.Error = "路由器上存在同端口映射，但内部地址或端口不一致"
				}
				break
			}
		}
		out.Managed = append(out.Managed, view)
	}
	for _, p := range all {
		key := fmt.Sprintf("%d/%s", p.ExternalPort, strings.ToUpper(p.Protocol))
		if used[key] {
			continue
		}
		out.External = append(out.External, ExternalMapping{
			ExternalPort: int(p.ExternalPort), Protocol: strings.ToUpper(p.Protocol),
			InternalPort: int(p.InternalPort), InternalClient: p.InternalClient,
			Description: p.Description, Enabled: p.Enabled,
		})
	}
	out.PausedReason = m.paused
	return out
}

func (m *Manager) Status(force bool) StatusView {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx := context.Background()
	gw := m.igd.Status(ctx, force)
	st := m.store.Snapshot()
	view := StatusView{
		Connected: gw.Connected, ExternalIP: gw.ExternalIP,
		Gateway: gw.ModelName, GatewayIP: gw.GatewayIP, Error: gw.Error,
		Managed: len(st.Forwards), PausedReason: m.paused, LastReapply: m.lastReapplyText,
	}
	if !gw.Connected {
		return view
	}
	snap := m.mappingsLocked(true)
	if snap.Error != "" {
		view.Error = snap.Error
		return view
	}
	for _, x := range snap.Managed {
		if x.Active {
			view.Active++
		} else {
			view.Missing++
		}
	}
	return view
}

func (m *Manager) Discover() StatusView {
	return m.Status(true)
}

func (m *Manager) validate(p AddPayload) (core.Forward, error) {
	f := core.Forward{
		Description:    strings.TrimSpace(p.Description),
		Protocol:       strings.ToUpper(strings.TrimSpace(p.Protocol)),
		ExternalPort:   p.ExternalPort,
		InternalPort:   p.InternalPort,
		InternalClient: strings.TrimSpace(p.InternalClient),
		LeaseTime:      p.LeaseTime,
		CreatedAt:      m.now(),
	}
	if f.Protocol != "TCP" && f.Protocol != "UDP" {
		return f, fmt.Errorf("协议只能是 TCP 或 UDP")
	}
	if f.ExternalPort < 1 || f.ExternalPort > 65535 || f.InternalPort < 1 || f.InternalPort > 65535 {
		return f, fmt.Errorf("端口必须在 1-65535 之间")
	}
	if f.LeaseTime < 0 {
		return f, fmt.Errorf("租期不能为负数")
	}
	if f.InternalClient == "" {
		f.InternalClient = detectLANIP()
	}
	if f.InternalClient == "" {
		return f, fmt.Errorf("无法自动检测本机局域网 IP，请手动填写内部 IP")
	}
	if net.ParseIP(f.InternalClient) == nil {
		return f, fmt.Errorf("内部 IP 格式不正确：%s", f.InternalClient)
	}
	return f, nil
}

func (m *Manager) Add(p AddPayload) (core.Forward, error) {
	f, err := m.validate(p)
	if err != nil {
		return f, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.store.Snapshot()
	for _, x := range st.Forwards {
		if x.ExternalPort == f.ExternalPort && x.Protocol == f.Protocol {
			return f, fmt.Errorf("外部端口 %d/%s 已有一条映射记录", f.ExternalPort, f.Protocol)
		}
	}
	ctx := context.Background()
	existing, err := m.igd.GetSpecific(ctx, f.ExternalPort, f.Protocol)
	if err != nil {
		return f, err
	}
	if existing != nil {
		return f, fmt.Errorf("外部端口 %d/%s 已被路由器上的其他映射占用（%s:%d）",
			f.ExternalPort, f.Protocol, existing.InternalClient, existing.InternalPort)
	}
	if err := m.igd.AddMapping(ctx, f.ExternalPort, f.Protocol, f.InternalPort,
		f.InternalClient, f.Description, f.LeaseTime); err != nil {
		return f, err
	}
	f.ID = randomID()
	if err := m.store.Update(func(s *core.State) error {
		s.Forwards = append(s.Forwards, f)
		return nil
	}); err != nil {
		return f, err
	}
	m.bus.Publish("forward", "info", "已添加映射 %s %d → %s:%d", f.Protocol, f.ExternalPort, f.InternalClient, f.InternalPort)
	return f, nil
}

func (m *Manager) Delete(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.store.Snapshot()
	var target *core.Forward
	for i := range st.Forwards {
		if st.Forwards[i].ID == id {
			target = &st.Forwards[i]
			break
		}
	}
	if target == nil {
		return "", errors.New("映射记录不存在")
	}
	warning := ""
	if err := m.igd.DeleteMapping(context.Background(), target.ExternalPort, target.Protocol); err != nil {
		msg := friendlyError(err)
		if !strings.Contains(msg, "不存在") {
			warning = "路由器映射删除失败：" + msg + "（本地记录已移除）"
		}
	}
	if err := m.store.Update(func(s *core.State) error {
		kept := make([]core.Forward, 0, len(s.Forwards))
		for _, x := range s.Forwards {
			if x.ID != id {
				kept = append(kept, x)
			}
		}
		s.Forwards = kept
		return nil
	}); err != nil {
		return "", err
	}
	m.bus.Publish("forward", "info", "已删除映射 %s %d", target.Protocol, target.ExternalPort)
	return warning, nil
}

func (m *Manager) Enable(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.store.Snapshot()
	var target *core.Forward
	for i := range st.Forwards {
		if st.Forwards[i].ID == id {
			target = &st.Forwards[i]
			break
		}
	}
	if target == nil {
		return errors.New("映射记录不存在")
	}
	if err := m.igd.AddMapping(context.Background(), target.ExternalPort, target.Protocol,
		target.InternalPort, target.InternalClient, target.Description, target.LeaseTime); err != nil {
		return err
	}
	m.bus.Publish("forward", "info", "已重新启用映射 %s %d", target.Protocol, target.ExternalPort)
	return nil
}

func (m *Manager) DeleteExternal(port int, proto string) error {
	if port < 1 || port > 65535 {
		return errors.New("端口不合法")
	}
	proto = strings.ToUpper(proto)
	if proto != "TCP" && proto != "UDP" {
		return errors.New("协议只能是 TCP 或 UDP")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.igd.DeleteMapping(context.Background(), port, proto); err != nil {
		return err
	}
	if err := m.store.Update(func(s *core.State) error {
		kept := make([]core.Forward, 0, len(s.Forwards))
		for _, x := range s.Forwards {
			if x.ExternalPort == port && strings.EqualFold(x.Protocol, proto) {
				continue
			}
			kept = append(kept, x)
		}
		s.Forwards = kept
		return nil
	}); err != nil {
		return err
	}
	m.bus.Publish("forward", "info", "已清理其他设备添加的映射 %s %d", proto, port)
	return nil
}

// Reapply 把本地记录中路由器上缺失的映射补回去。
// force=true 时忽略网关指纹保护（用户手动点「重新下发」）。
func (m *Manager) Reapply(force bool) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.store.Snapshot()
	if !force && !st.Settings.AutoReapply {
		return 0, errors.New("自动补发已在设置中关闭")
	}
	all, _, err := m.enumerate(st)
	if err != nil {
		return 0, err
	}
	if m.paused != "" && !force {
		return 0, errors.New(m.paused)
	}
	count := 0
	for _, f := range st.Forwards {
		found := false
		for _, p := range all {
			if sameMapping(f, p) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		if err := m.igd.AddMapping(context.Background(), f.ExternalPort, f.Protocol,
			f.InternalPort, f.InternalClient, f.Description, f.LeaseTime); err != nil {
			m.log.Warn("补发映射 %s %d 失败: %v", f.Protocol, f.ExternalPort, err)
			continue
		}
		count++
	}
	m.lastReapply = time.Now()
	m.lastReapplyText = m.now()
	if count > 0 {
		m.bus.Publish("forward", "info", "已补发 %d 条丢失的映射", count)
	}
	return count, nil
}

func (m *Manager) tick() {
	st := m.store.Snapshot()
	if !st.Settings.AutoReapply || len(st.Forwards) == 0 {
		return
	}
	interval := time.Duration(st.Settings.ReapplyInterval) * time.Second
	m.mu.Lock()
	due := time.Since(m.lastReapply) >= interval
	m.mu.Unlock()
	if !due {
		return
	}
	if _, err := m.Reapply(false); err != nil {
		m.log.Debug("自动补发跳过: %v", err)
	}
}

func (m *Manager) Summarize() map[string]interface{} {
	s := m.Status(false)
	return map[string]interface{}{
		"connected":   s.Connected,
		"external_ip": s.ExternalIP,
		"managed":     s.Managed,
		"active":      s.Active,
		"missing":     s.Missing,
		"error":       s.Error,
	}
}
