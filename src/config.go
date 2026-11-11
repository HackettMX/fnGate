package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fngate/cert"
)

// Config 全部来自环境变量，命令行 flag 仅用于本地调试。
// 生产环境只经统一网关 Unix Socket 提供服务，不监听管理 TCP 端口。
type Config struct {
	WebHost       string
	WebPort       int
	DataDir       string
	StateFile     string
	SecretsDir    string
	CertsDir      string
	SocketPath    string
	GatewayPrefix string
	LogLevel      string
	SysCertConf   string
	SysCertExtra  string
	SysConfPaths  []string
	SysSSLRoots   []string
	SysAllowed    []string
}

func envString(names []string, def string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return def
}

func envInt(names []string, def int) int {
	raw := envString(names, "")
	if n, err := strconv.Atoi(raw); err == nil {
		return n
	}
	return def
}

// envList 用系统路径分隔符切分（Linux 为 :，Windows 为 ;），
// 避免把 Windows 盘符里的冒号误当成列表分隔符。
func envList(names []string, def []string) []string {
	raw := strings.TrimSpace(envString(names, ""))
	if raw == "" {
		return def
	}
	parts := filepath.SplitList(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func prependUnique(primary []string, rest []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(primary)+len(rest))
	for _, p := range append(append([]string{}, primary...), rest...) {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func LoadConfig(dataFlag string, webPortFlag int) Config {
	dataDir := dataFlag
	if dataDir == "" {
		dataDir = envString([]string{"FNGATE_DATA_DIR", "TRIM_PKGVAR"}, "./data")
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	webPort := webPortFlag
	if webPort == 0 {
		webPort = envInt([]string{"FNGATE_WEB_PORT"}, 9583)
	}
	cfg := Config{
		WebHost:       envString([]string{"FNGATE_WEB_HOST"}, "127.0.0.1"),
		WebPort:       webPort,
		DataDir:       dataDir,
		StateFile:     filepath.Join(dataDir, "state.json"),
		SecretsDir:    filepath.Join(dataDir, "secrets"),
		CertsDir:      filepath.Join(dataDir, "certs"),
		SocketPath:    envString([]string{"FNGATE_SOCKET"}, ""),
		GatewayPrefix: strings.TrimSuffix(envString([]string{"FNGATE_GATEWAY_PREFIX"}, "/app/fngate"), "/"),
		LogLevel:      strings.ToUpper(envString([]string{"FNGATE_LOG_LEVEL"}, "INFO")),
		// root helper 读取的系统证书索引，只允许固定白名单路径，不接受前端传参。
		SysCertConf:  envString([]string{"FNGATE_SYS_CERT_CONF"}, "/usr/trim/etc/network_cert_all.conf"),
		SysCertExtra: envString([]string{"FNGATE_SYS_CERT_EXTRA"}, "/usr/trim/etc/network_gateway_cert.conf"),
	}
	// 多路径探测：环境变量优先，随后补上各 fnOS 版本常见位置。
	cfg.SysConfPaths = prependUnique(
		envList([]string{"FNGATE_SYS_CERT_PATHS"}, nil),
		prependUnique([]string{cfg.SysCertConf, cfg.SysCertExtra}, cert.DefaultConfPaths()),
	)
	cfg.SysSSLRoots = prependUnique(envList([]string{"FNGATE_SYS_CERT_SSL_ROOTS"}, nil), cert.DefaultSSLRoots())
	cfg.SysAllowed = prependUnique(envList([]string{"FNGATE_SYS_CERT_ROOTS"}, nil), cert.DefaultAllowedRoots())
	return cfg
}
