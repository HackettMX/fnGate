package forward

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp"
	igd1 "github.com/huin/goupnp/dcps/internetgateway1"
	igd2 "github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"
)

const (
	// maxMappings 限制 NAT 表枚举上限，防止异常路由器返回无限条目。
	maxMappings = 256
	// soapTimeout 是单次 SOAP 调用的超时。
	soapTimeout = 10 * time.Second
	// igdSearchTarget 是 IGD 设备的 SSDP 搜索目标。
	igdSearchTarget = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	// rootSearchTarget 作为兜底搜索，兼容少数不响应 IGD ST 的路由器。
	rootSearchTarget = "upnp:rootdevice"
	// externalIPCacheFor 是公网 IP 的微缓存时间，减少前端轮询对路由器的压力。
	externalIPCacheFor = 5 * time.Second
	// failedDiscoveryCache 是发现失败的负缓存时间，避免无路由器时反复扫描。
	failedDiscoveryCache = 15 * time.Second
)

// errNoGateway 表示局域网内没有可用的 UPnP 网关。
var errNoGateway = errors.New("未发现支持 UPnP 的路由器。请确认路由器已开启 UPnP，且本机与路由器在同一局域网。")

// PortMapping 对应路由器 NAT 表中的一条端口映射。
type PortMapping struct {
	RemoteHost     string
	ExternalPort   uint16
	Protocol       string
	InternalPort   uint16
	InternalClient string
	Enabled        bool
	Description    string
	LeaseDuration  uint32
}

// GatewayStatus 是网关状态的只读快照。
type GatewayStatus struct {
	Connected    bool
	GatewayIP    string
	ExternalIP   string
	ModelName    string
	Manufacturer string
	ServiceType  string
	Error        string
}

// igdConn 统一封装 IGD1/IGD2 的 WANIPConnection 与 WANPPPConnection 客户端。
// 只保留一个非 nil 字段，表示实际可用的服务类型。
type igdConn struct {
	kind string
	loc  *url.URL
	root *goupnp.RootDevice
	ip1  *igd1.WANIPConnection1
	ppp1 *igd1.WANPPPConnection1
	ip2  *igd2.WANIPConnection2
}

func (c *igdConn) externalIP(ctx context.Context) (string, error) {
	switch {
	case c.ip1 != nil:
		return c.ip1.GetExternalIPAddressCtx(ctx)
	case c.ppp1 != nil:
		return c.ppp1.GetExternalIPAddressCtx(ctx)
	case c.ip2 != nil:
		return c.ip2.GetExternalIPAddressCtx(ctx)
	}
	return "", errors.New("路由器不支持查询公网 IP")
}

// addPortMapping 添加映射。部分国产路由器/光猫对 UPnP 参数格外挑剔，
// 对完全合规的请求也返回 402 Invalid Args。这里按序降级重试：
//  1. 空 RemoteHost + 原样租期（标准写法，绝大多数路由器接受）
//  2. RemoteHost="*" + 原样租期（少数固件不接受空串）
//  3. 空 RemoteHost + 有限租期（部分光猫不接受 LeaseDuration=0 表示永久）
//  4. RemoteHost="*" + 有限租期
//
// 400/501/718 等明确错误不重试，避免掩盖真实问题。
// portMappingVariant 是一次 AddPortMapping 调用的参数组合。
type portMappingVariant struct {
	remoteHost string
	lease      uint32
}

// portMappingVariants 生成 402 降级重试的参数组合。
// 顺序有讲究：标准写法优先，尽量不改变路由器上的实际语义。
func portMappingVariants(lease uint32) []portMappingVariant {
	variants := []portMappingVariant{{"", lease}, {"*", lease}}
	if lease == 0 {
		// LeaseDuration=0 在规范里代表永久，但不少路由器直接判为非法参数。
		// 用 86400 秒（1 天）兜底，配合应用的自动补发，实际仍是"永久"效果。
		variants = append(variants, portMappingVariant{"", 86400}, portMappingVariant{"*", 86400})
	}
	return variants
}

// tryPortMappingVariants 按序尝试参数组合：成功即返回；仅 402 才继续降级，
// 其它错误（如 718 端口冲突）立即返回，避免把真实故障伪装成"参数不兼容"。
func tryPortMappingVariants(variants []portMappingVariant, call func(portMappingVariant) error) error {
	var lastErr error
	for _, v := range variants {
		if err := call(v); err == nil {
			return nil
		} else {
			lastErr = err
			if upnpErrorCode(err) != 402 {
				return err
			}
		}
	}
	return lastErr
}

func (c *igdConn) addPortMapping(ctx context.Context, extPort uint16, protocol string, intPort uint16, client, description string, lease uint32) error {
	return tryPortMappingVariants(portMappingVariants(lease), func(v portMappingVariant) error {
		return c.addPortMappingOnce(ctx, v.remoteHost, extPort, protocol, intPort, client, description, v.lease)
	})
}

// addPortMappingOnce 发起单次 SOAP 调用。抽成函数便于单测注入不同固件的响应。
func (c *igdConn) addPortMappingOnce(ctx context.Context, remoteHost string, extPort uint16, protocol string, intPort uint16, client, description string, lease uint32) error {
	switch {
	case c.ip1 != nil:
		return c.ip1.AddPortMappingCtx(ctx, remoteHost, extPort, protocol, intPort, client, true, description, lease)
	case c.ppp1 != nil:
		return c.ppp1.AddPortMappingCtx(ctx, remoteHost, extPort, protocol, intPort, client, true, description, lease)
	case c.ip2 != nil:
		return c.ip2.AddPortMappingCtx(ctx, remoteHost, extPort, protocol, intPort, client, true, description, lease)
	}
	return errors.New("路由器不支持添加端口映射")
}

func (c *igdConn) deletePortMapping(ctx context.Context, extPort uint16, protocol string) error {
	switch {
	case c.ip1 != nil:
		return c.ip1.DeletePortMappingCtx(ctx, "", extPort, protocol)
	case c.ppp1 != nil:
		return c.ppp1.DeletePortMappingCtx(ctx, "", extPort, protocol)
	case c.ip2 != nil:
		return c.ip2.DeletePortMappingCtx(ctx, "", extPort, protocol)
	}
	return errors.New("路由器不支持删除端口映射")
}

func (c *igdConn) genericEntry(ctx context.Context, index uint16) (PortMapping, error) {
	var (
		mapping PortMapping
		enabled bool
		err     error
	)
	switch {
	case c.ip1 != nil:
		mapping.RemoteHost, mapping.ExternalPort, mapping.Protocol, mapping.InternalPort,
			mapping.InternalClient, enabled, mapping.Description, mapping.LeaseDuration, err =
			c.ip1.GetGenericPortMappingEntryCtx(ctx, index)
	case c.ppp1 != nil:
		mapping.RemoteHost, mapping.ExternalPort, mapping.Protocol, mapping.InternalPort,
			mapping.InternalClient, enabled, mapping.Description, mapping.LeaseDuration, err =
			c.ppp1.GetGenericPortMappingEntryCtx(ctx, index)
	case c.ip2 != nil:
		mapping.RemoteHost, mapping.ExternalPort, mapping.Protocol, mapping.InternalPort,
			mapping.InternalClient, enabled, mapping.Description, mapping.LeaseDuration, err =
			c.ip2.GetGenericPortMappingEntryCtx(ctx, index)
	default:
		return mapping, errors.New("路由器不支持枚举端口映射")
	}
	mapping.Enabled = enabled
	return mapping, err
}

func (c *igdConn) specificEntry(ctx context.Context, extPort uint16, protocol string) (PortMapping, error) {
	var (
		mapping PortMapping
		enabled bool
		err     error
	)
	mapping.ExternalPort = extPort
	mapping.Protocol = protocol
	switch {
	case c.ip1 != nil:
		mapping.InternalPort, mapping.InternalClient, enabled, mapping.Description, mapping.LeaseDuration, err =
			c.ip1.GetSpecificPortMappingEntryCtx(ctx, "", extPort, protocol)
	case c.ppp1 != nil:
		mapping.InternalPort, mapping.InternalClient, enabled, mapping.Description, mapping.LeaseDuration, err =
			c.ppp1.GetSpecificPortMappingEntryCtx(ctx, "", extPort, protocol)
	case c.ip2 != nil:
		mapping.InternalPort, mapping.InternalClient, enabled, mapping.Description, mapping.LeaseDuration, err =
			c.ip2.GetSpecificPortMappingEntryCtx(ctx, "", extPort, protocol)
	default:
		return mapping, errors.New("路由器不支持查询指定端口映射")
	}
	mapping.Enabled = enabled
	return mapping, err
}

// UPnPManager 负责 IGD 网关的发现、缓存与端口映射操作。
// 所有对外方法都是串行的：路由器 SOAP 接口并发能力弱，串行更稳定。
type UPnPManager struct {
	mu           sync.Mutex
	conn         *igdConn
	discoveredAt time.Time
	ttl          time.Duration
	discTimeout  time.Duration

	lastExternalIP   string
	lastExternalIPAt time.Time

	// 失败也缓存一小段时间：没有路由器时避免每个轮询周期都做一次 SSDP 扫描。
	lastAttemptAt  time.Time
	lastAttemptErr error
}

func NewUPnPManager(discoveryTimeout, ttl time.Duration) *UPnPManager {
	return &UPnPManager{ttl: ttl, discTimeout: discoveryTimeout}
}

// Status 返回网关状态；force 为 true 时强制重新发现。
func (m *UPnPManager) Status(ctx context.Context, force bool) GatewayStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if force || m.conn == nil || time.Since(m.discoveredAt) > m.ttl {
		if !force && m.recentFailureLocked() {
			return GatewayStatus{Error: friendlyError(m.lastAttemptErr)}
		}
		if err := m.discoverLocked(ctx); err != nil {
			return GatewayStatus{Error: friendlyError(err)}
		}
	}
	return m.snapshotLocked(ctx)
}

func (m *UPnPManager) snapshotLocked(ctx context.Context) GatewayStatus {
	status := GatewayStatus{
		Connected:    true,
		GatewayIP:    m.conn.loc.Hostname(),
		ModelName:    strings.TrimSpace(m.conn.root.Device.ModelName),
		Manufacturer: strings.TrimSpace(m.conn.root.Device.Manufacturer),
		ServiceType:  m.conn.kind,
	}
	if status.ModelName == "" {
		status.ModelName = strings.TrimSpace(m.conn.root.Device.FriendlyName)
	}
	ip, err := m.externalIPLocked(ctx)
	if err != nil {
		// 取不到公网 IP 说明网关已不可用，标记失效以便下次重新发现。
		status.Connected = false
		status.Error = friendlyError(err)
		m.conn = nil
		m.lastAttemptAt = time.Now()
		m.lastAttemptErr = err
		return status
	}
	status.ExternalIP = ip
	return status
}

func (m *UPnPManager) externalIPLocked(ctx context.Context) (string, error) {
	if m.lastExternalIP != "" && time.Since(m.lastExternalIPAt) < externalIPCacheFor {
		return m.lastExternalIP, nil
	}
	callCtx, cancel := context.WithTimeout(ctx, soapTimeout)
	defer cancel()
	ip, err := m.conn.externalIP(callCtx)
	if err != nil {
		return "", err
	}
	m.lastExternalIP = ip
	m.lastExternalIPAt = time.Now()
	return ip, nil
}

// ensureLocked 确保存在可用的网关连接，必要时重新发现。
func (m *UPnPManager) ensureLocked(ctx context.Context) error {
	if m.conn != nil && time.Since(m.discoveredAt) <= m.ttl {
		return nil
	}
	if m.recentFailureLocked() {
		return m.lastAttemptErr
	}
	return m.discoverLocked(ctx)
}

// recentFailureLocked 判断是否处于「刚刚发现失败」的负缓存窗口内。
func (m *UPnPManager) recentFailureLocked() bool {
	return m.conn == nil && m.lastAttemptErr != nil && time.Since(m.lastAttemptAt) < failedDiscoveryCache
}

func (m *UPnPManager) discoverLocked(ctx context.Context) error {
	err := m.scanAndConnectLocked(ctx)
	m.lastAttemptAt = time.Now()
	m.lastAttemptErr = err
	return err
}

func (m *UPnPManager) scanAndConnectLocked(ctx context.Context) error {
	m.conn = nil
	m.lastExternalIP = ""

	searchCtx, cancel := context.WithTimeout(ctx, m.discTimeout)
	devices, _ := goupnp.DiscoverDevicesCtx(searchCtx, igdSearchTarget)
	if len(devices) == 0 && searchCtx.Err() == nil {
		devices, _ = goupnp.DiscoverDevicesCtx(searchCtx, rootSearchTarget)
	}
	cancel()

	if len(devices) == 0 {
		return errNoGateway
	}

	var lastErr error
	for _, candidate := range devices {
		if candidate.Err != nil || candidate.Root == nil || candidate.Location == nil {
			continue
		}
		for _, conn := range buildConnections(candidate.Root, candidate.Location) {
			callCtx, callCancel := context.WithTimeout(ctx, soapTimeout)
			_, err := conn.externalIP(callCtx)
			callCancel()
			if err != nil {
				lastErr = err
				continue
			}
			m.conn = conn
			m.discoveredAt = time.Now()
			return nil
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errNoGateway
}

// buildConnections 按兼容性优先级构造候选连接：IGD1 优先，其次 IGD2。
func buildConnections(root *goupnp.RootDevice, loc *url.URL) []*igdConn {
	var out []*igdConn

	if clients, err := igd1.NewWANIPConnection1ClientsFromRootDevice(root, loc); err == nil {
		for _, client := range clients {
			out = append(out, &igdConn{kind: "WANIPConnection:1", loc: loc, root: root, ip1: client})
		}
	}
	if clients, err := igd1.NewWANPPPConnection1ClientsFromRootDevice(root, loc); err == nil {
		for _, client := range clients {
			out = append(out, &igdConn{kind: "WANPPPConnection:1", loc: loc, root: root, ppp1: client})
		}
	}
	if clients, err := igd2.NewWANIPConnection2ClientsFromRootDevice(root, loc); err == nil {
		for _, client := range clients {
			out = append(out, &igdConn{kind: "WANIPConnection:2", loc: loc, root: root, ip2: client})
		}
	}
	return out
}

// ListMappings 枚举路由器 NAT 表中的全部映射。
func (m *UPnPManager) ListMappings(ctx context.Context) ([]PortMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureLocked(ctx); err != nil {
		return nil, errNoGatewayOr(err)
	}

	out := make([]PortMapping, 0, 16)
	for index := 0; index < maxMappings; index++ {
		callCtx, cancel := context.WithTimeout(ctx, soapTimeout)
		entry, err := m.conn.genericEntry(callCtx, uint16(index))
		cancel()
		if err != nil {
			// 713/714 表示索引不存在，是枚举走到末尾的正常信号。
			if code := upnpErrorCode(err); code == 713 || code == 714 {
				return out, nil
			}
			// 一条都没取到就失败，说明枚举本身不可信（路由器忙、UPnP 半死等），
			// 必须把错误抛出去，否则会被当成"路由器上一条映射都没有"。
			if len(out) == 0 {
				return out, errors.New(friendlyError(err))
			}
			// 已取到部分条目：返回已拿到的，避免整页空白。
			return out, nil
		}
		out = append(out, entry)
	}
	return out, nil
}

// GetSpecific 查询单条映射；不存在时返回 (nil, nil)。
func (m *UPnPManager) GetSpecific(ctx context.Context, externalPort int, protocol string) (*PortMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureLocked(ctx); err != nil {
		return nil, errNoGatewayOr(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, soapTimeout)
	defer cancel()
	entry, err := m.conn.specificEntry(callCtx, uint16(externalPort), protocol)
	if err != nil {
		code := upnpErrorCode(err)
		if code == 714 {
			return nil, nil
		}
		if code == 402 {
			// 部分固件对 GetSpecificPortMappingEntry 也返回 Invalid Args，
			// 导致无法预检冲突。此时不阻断添加：AddMapping 侧有 402 降级重试，
			// 真有冲突时路由器会返回 718，提示比卡在 402 更明确。
			return nil, nil
		}
		return nil, errors.New(friendlyError(err))
	}
	return &entry, nil
}

// explainInternalClient 针对 402 + 非本机 InternalClient 补充解释。
// 家用路由器 UPnP 普遍只允许把端口映射到发起请求的设备自身，拒绝替
// 局域网内其他设备开洞。这是固件安全限制，换 RemoteHost/租期绕不过。
// local 由调用方注入便于单测；为空或 client==local 时原样返回。
func explainInternalClient(err error, client, local string) error {
	if upnpErrorCode(err) != 402 || client == "" || local == "" || strings.EqualFold(client, local) {
		return err
	}
	return fmt.Errorf("%s。注意：内部 IP %s 不是本机地址（本机 %s）。多数家用路由器的 UPnP 只允许把端口映射到发起请求的设备自身，"+
		"不允许替局域网内其他设备开洞，这是路由器的安全限制，换端口或租期都无法绕过。"+
		"要让 %s 上的服务对外可访问，请改用「反向代理」新建一条指向 %s 的 TCP 入口后映射本机端口，或在路由器管理页手动添加端口转发。",
		friendlyError(err), client, local, client, client)
}

// AddMapping 在路由器上新增（或覆盖）一条端口映射。
func (m *UPnPManager) AddMapping(ctx context.Context, externalPort int, protocol string, internalPort int, internalClient, description string, leaseTime int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureLocked(ctx); err != nil {
		return errNoGatewayOr(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, soapTimeout)
	defer cancel()
	if err := m.conn.addPortMapping(callCtx, uint16(externalPort), protocol, uint16(internalPort), internalClient, description, uint32(leaseTime)); err != nil {
		return explainInternalClient(err, internalClient, detectLANIP())
	}
	return nil
}

// DeleteMapping 删除路由器上的端口映射。
func (m *UPnPManager) DeleteMapping(ctx context.Context, externalPort int, protocol string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureLocked(ctx); err != nil {
		return errNoGatewayOr(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, soapTimeout)
	defer cancel()
	if err := m.conn.deletePortMapping(callCtx, uint16(externalPort), protocol); err != nil {
		return errors.New(friendlyError(err))
	}
	return nil
}

func errNoGatewayOr(err error) error {
	if errors.Is(err, errNoGateway) {
		return err
	}
	return errors.New(friendlyError(err))
}

var upnpCodePattern = regexp.MustCompile(`<errorCode>\s*(\d+)\s*</errorCode>`)
var upnpDescPattern = regexp.MustCompile(`(?is)<errorDescription[^>]*>(.*?)</errorDescription>`)

func extractXMLTag(raw, tag string) string {
	if tag != "errorDescription" {
		return ""
	}
	match := upnpDescPattern.FindStringSubmatch(raw)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func upnpErrorCode(err error) int {
	var fault *soap.SOAPFaultError
	if errors.As(err, &fault) {
		if code := fault.Detail.UPnPError.Errorcode; code != 0 {
			return code
		}
		if match := upnpCodePattern.FindStringSubmatch(string(fault.Detail.Raw)); len(match) == 2 {
			if code, convErr := strconv.Atoi(match[1]); convErr == nil {
				return code
			}
		}
	}
	return 0
}

var upnpErrorText = map[int]string{
	402: "路由器返回参数错误（Invalid Args）",
	501: "路由器拒绝了操作，可能 UPnP 被禁用或权限不足",
	606: "路由器不支持该操作",
	713: "映射索引不存在",
	714: "该端口映射不存在",
	715: "通配符 IP 不被允许",
	716: "外部端口必须为 0（WildCardPortNotSupported）",
	718: "该外部端口已被其他映射占用（ConflictInMappingEntry）",
	724: "内部端口与外部端口不一致不被允许",
	725: "路由器仅支持永久租期",
	726: "路由器仅支持固定租期",
	727: "外部端口必须小于内部端口",
	728: "路由器无可用端口映射资源（NoPortMapsAvailable）",
	729: "路由器不支持该协议",
	732: "该协议不被支持",
	733: "内部端口与外部端口不能相同",
}

// friendlyError 把底层异常翻译成面向用户的中文提示，不暴露堆栈细节。
func friendlyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errNoGateway) {
		return errNoGateway.Error()
	}
	if message := err.Error(); strings.Contains(message, "未发现支持 UPnP") {
		return message
	}

	var fault *soap.SOAPFaultError
	if errors.As(err, &fault) {
		// 路由器的原始描述往往直接说明被拒的参数（如 LeaseDuration、
		// InternalClient），务必保留，否则 402 只剩一句"参数错误"无从排查。
		desc := strings.TrimSpace(fault.Detail.UPnPError.ErrorDescription)
		if match := upnpCodePattern.FindStringSubmatch(string(fault.Detail.Raw)); len(match) == 2 && desc == "" {
			desc = strings.TrimSpace(extractXMLTag(string(fault.Detail.Raw), "errorDescription"))
		}
		if text, ok := upnpErrorText[upnpErrorCode(err)]; ok {
			if desc != "" && desc != text {
				return text + "：" + desc
			}
			return text
		}
		if desc != "" {
			return "路由器拒绝操作：" + desc
		}
		return "路由器返回错误：" + fault.FaultString
	}

	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return "连接路由器超时，请检查网络或路由器 UPnP 状态"
	}

	message := err.Error()
	switch {
	case strings.Contains(message, "connection refused"):
		return "无法连接路由器网关，请检查网络连通性"
	case strings.Contains(message, "no route to host"):
		return "无法到达路由器网关，请检查本机与路由器是否在同一局域网"
	case strings.Contains(message, "no such host"):
		return "无法解析路由器地址，请重新发现网关"
	case strings.Contains(message, "EOF"):
		return "路由器中断了连接，请稍后重试"
	case strings.Contains(message, "connection reset"):
		return "路由器重置了连接，请稍后重试"
	}
	return "操作失败：" + message
}

// detectLANIP 探测本机局域网 IP。
// 不能只用 UDP connect：NAS 上 Clash/Surge 的 fake-ip 会把出口地址改写成
// 198.18.x.x，导致误判"填了非本机 IP"。因此优先枚举真实网卡：
// 取第一个私网 IPv4（排除回环、link-local 与 fake-ip 段），UDP 仅作兜底。
func detectLANIP() string {
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !ip.IsPrivate() || isFakeLANIP(ip) {
				continue
			}
			return ip.String()
		}
	}
	conn, err := net.Dial("udp", "223.5.5.5:53")
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && !isFakeLANIP(addr.IP) {
		return addr.IP.String()
	}
	return ""
}

// isFakeLANIP 与 acme.isHijackedIP 同口径，识别 fake-ip 占用的测试保留段。
func isFakeLANIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
		return true
	}
	return false
}

// randomID 生成 12 位十六进制随机标识。
func randomID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	return hex.EncodeToString(buf)
}
