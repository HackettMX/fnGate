// Package deployer 是飞牛 fnOS「系统 HTTPS 证书替换」的 root 侧受限引擎。
//
// 设计参考已在 fnOS 1.2.0602 真机验证的开源实现（fnos-deployment-engine），
// 用 Go 标准库重写。核心原则：fnOS 证书存储是内部接口，任何一步（数据库、
// 索引、PEM、网关映射、实时 TLS）不一致都 fail-closed，绝不带着不确定状态写入。
//
// 本包只被 root 生命周期拉起的 --cert-deployer 守护进程使用；主应用通过受限
// Unix Socket 调用 status/prepare/deploy，无法传入任意路径。
package deployer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// 系统固定路径。全部为 fnOS 内部实现，集中于此，便于随版本调整。
const (
	CertRoot     = "/usr/trim/var/trim_connect/ssls"
	IndexPath    = "/usr/trim/etc/network_cert_all.conf"
	GatewayPath  = "/usr/trim/etc/network_gateway_cert.conf"
	NginxConf    = "/usr/trim/nginx/conf/nginx.conf"
	StateDir     = "/var/lib/fngate-cert-deployer"
	DefaultSock  = "/run/fngate-cert-deployer/control.sock"
	DefaultRunDir = "/run/fngate-cert-deployer"
	DBName       = "trim_connect"
)

// 错误码：客户端据此给出可读中文提示，且不泄漏系统内部细节。
type Code string

const (
	CodeUnavailable  Code = "UNAVAILABLE"
	CodeIncompatible Code = "INCOMPATIBLE"
	CodeProtected    Code = "PROTECTED"
	CodeInvalid      Code = "INVALID"
	CodeUntrusted    Code = "UNTRUSTED"
	CodeDomain       Code = "DOMAIN"
	CodeConflict     Code = "CONFLICT"
	CodeTLS          Code = "TLS"
	CodeBusy         Code = "BUSY"
	CodeRolledBack   Code = "ROLLED_BACK"
	CodeRecovery     Code = "RECOVERY"
)

var codeText = map[Code]string{
	CodeUnavailable:  "内置部署服务未连接，请重启主应用后重试",
	CodeIncompatible: "系统证书结构或权限不兼容，未执行部署",
	CodeProtected:    "仅支持已手动导入的证书，不修改 fnOS 自带证书",
	CodeInvalid:      "证书、私钥、证书链或有效期校验未通过",
	CodeUntrusted:    "新证书链不受公共 CA 信任，请使用正式签发的完整证书链",
	CodeDomain:       "新旧证书域名必须完全一致，验证域名必须包含在证书中",
	CodeConflict:     "系统证书或配置已变化，请重新预检",
	CodeTLS:          "本机 HTTPS 验证未通过，请核对系统 HTTPS 端口和绑定域名",
	CodeBusy:         "已有部署任务正在运行，请稍后重试",
	CodeRolledBack:   "部署未成功，已恢复原证书并验证 HTTPS",
	CodeRecovery:     "部署恢复未完成，已停止后续写入；请在 fnOS 检查证书与 HTTPS 服务",
}

func Text(c Code) string {
	if s, ok := codeText[c]; ok {
		return s
	}
	return codeText[CodeIncompatible]
}

// DeployError 携带错误码与阶段，便于回滚日志与前端展示。
// Detail 是脱敏后的逐行诊断，只对 status/diagnose 暴露，不含私钥或系统路径以外的内容。
type DeployError struct {
	Code   Code
	Stage  string
	Detail string
}

func (e *DeployError) Error() string {
	if e.Detail != "" {
		return Text(e.Code) + "：" + e.Detail
	}
	return Text(e.Code)
}

func fail(c Code) error { return &DeployError{Code: c} }

func failStage(c Code, stage string) error { return &DeployError{Code: c, Stage: stage} }

// failDetail 给失败附上可展示的脱敏诊断（不含私钥内容）。
func failDetail(c Code, stage, detail string) error {
	return &DeployError{Code: c, Stage: stage, Detail: detail}
}

// detailOf 取出错误里的诊断文本。
func detailOf(err error) string {
	var de *DeployError
	if errors.As(err, &de) {
		return de.Detail
	}
	return ""
}

// codeOf 从错误中提取 DeployError（若非本包错误则返回 INCOMPATIBLE）。
func codeOf(err error) Code {
	var de *DeployError
	if errors.As(err, &de) {
		return de.Code
	}
	return CodeIncompatible
}

// HTTP 状态码：BUSY/CONFLICT 为 409，其余写操作错误为 400。
func statusOf(err error) int {
	c := codeOf(err)
	if c == CodeBusy || c == CodeConflict {
		return 409
	}
	return 400
}

// 阶段名，与失败 journal 中的 stage 对应。
const (
	StageMetadata    = "metadata"
	StageFiles       = "files"
	StageRestart     = "restart"
	StageVerify      = "verify"
	StageConsistency = "consistency"
)

// Target 是目标证书（Database cert 行 + 索引条目）的公开视图。
type Target struct {
	ID            string   `json:"id"`
	Domains       []string `json:"domains"`
	ValidTo       string   `json:"valid_to"`
	Fingerprint   string   `json:"fingerprint"`
	Bound         bool     `json:"bound"`
	ProbeHost     string   `json:"probe_host"`
	VerifiedPorts []int    `json:"verified_ports"`
	Reason        string   `json:"reason,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// StatusResult 是 /status 的响应。
type StatusResult struct {
	Available       bool     `json:"available"`
	Experimental    bool     `json:"experimental"`
	Targets         []Target `json:"targets"`
	Unavailable     []Target `json:"unavailable_targets"`
	Skipped         int      `json:"skipped"`
	Running         bool     `json:"running"`
	Ports           []int    `json:"ports,omitempty"`
	RecoveryFailed  bool     `json:"recovery_failed,omitempty"`
	Diagnostics     []string `json:"diagnostics,omitempty"`
}

// PrepareInput 是 /prepare 与 /deploy 共享的输入。
type PrepareInput struct {
	TargetID          string `json:"target_id"`
	CertificatePEM    string `json:"certificate_pem"`
	PrivateKeyPEM     string `json:"private_key_pem"`
	ProbeHost         string `json:"probe_host"`
	ProbePort         int    `json:"probe_port"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
	PlanID            string `json:"plan_id,omitempty"`
}

// PrepareResult 是 /prepare 的响应。
type PrepareResult struct {
	PlanID      string   `json:"plan_id"`
	Target      Target   `json:"target"`
	Fingerprint string   `json:"fingerprint"`
	ValidTo     string   `json:"valid_to"`
	ProbeHost   string   `json:"probe_host"`
	ProbePort   int      `json:"probe_port"`
	Domains     []string `json:"domains"`
}

// DeployResult 是 /deploy 的响应。
type DeployResult struct {
	OK          bool   `json:"ok"`
	Fingerprint string `json:"fingerprint"`
	ValidTo     string `json:"valid_to"`
	VerifiedAt  string `json:"verified_at"`
}

// ---------- 通用工具 ----------

func cleanDomains(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(v, ".")))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// canonicalJSON 提供与参考实现 canonical() 等价的稳定 JSON：map key 排序后编码。
func canonicalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func equalJSON(a, b interface{}) bool {
	return canonicalJSON(a) == canonicalJSON(b)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fingerprint256 返回与 Node X509Certificate.fingerprint256 一致的格式（大写冒号分隔）。
func fingerprint256(der []byte) string {
	sum := sha256.Sum256(der)
	s := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

func normalizeFP(s string) string {
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return strings.ToLower(s)
}

func sameFingerprint(a, b string) bool {
	return normalizeFP(a) != "" && normalizeFP(a) == normalizeFP(b)
}

// jsonNumber 把整数毫秒转成 json.Number，保证序列化后是数字而非字符串。
func jsonNumber(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

func marshalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// 证书解析结果。
type parsedCert struct {
	Chain       []*x509.Certificate
	Leaf        *x509.Certificate
	Domains     []string
	Fingerprint string
	ValidFromMS int64
	ValidToMS   int64
	EncryptType string
	IssuedBy    string
	ChainPEM    []byte
	IssuerPEM   []byte
}

// 供探测用的 TCP 端口范围校验。
func validPort(p int) bool { return p > 0 && p <= 65535 }

// splitHostPort 供探测地址校验（部署探测连接固定 127.0.0.1，仅用端口）。
func loopbackAddr(port int) string { return net.JoinHostPort("127.0.0.1", fmt.Sprint(port)) }
