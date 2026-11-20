package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	SocketPath     string
	DeployerSocket string
	GatewayPrefix  string
	LogLevel       string
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
	return Config{
		WebHost:       envString([]string{"FNGATE_WEB_HOST"}, "127.0.0.1"),
		WebPort:       webPort,
		DataDir:       dataDir,
		StateFile:     filepath.Join(dataDir, "state.json"),
		SecretsDir:    filepath.Join(dataDir, "secrets"),
		CertsDir:      filepath.Join(dataDir, "certs"),
		SocketPath:     envString([]string{"FNGATE_SOCKET"}, ""),
		DeployerSocket: envString([]string{"FNGATE_DEPLOYER_SOCKET"}, ""),
		GatewayPrefix:  strings.TrimSuffix(envString([]string{"FNGATE_GATEWAY_PREFIX"}, "/app/fngate"), "/"),
		LogLevel:      strings.ToUpper(envString([]string{"FNGATE_LOG_LEVEL"}, "INFO")),
	}
}
