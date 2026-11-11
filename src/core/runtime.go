package core

import (
	"os"
	"os/user"
	"strconv"
	"strings"
)

// capNetBindService 是 CAP_NET_BIND_SERVICE 在 CapEff 位图中的位（bit 10）。
const capNetBindService uint64 = 1 << 10

func RuntimeUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return strconv.Itoa(os.Getuid())
}

func EUID() int { return os.Geteuid() }

// CanBindLowPort 判断是否具备绑定 1024 以下端口的能力。
// 用 /proc/self/status 的 CapEff 判断，比"试着 bind :80"更可靠——
// 80 被别的服务占用时会误判成无权限。
func CanBindLowPort() bool {
	if os.Geteuid() == 0 {
		return true
	}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		// 非 Linux（本地调试）不阻断，实际绑定失败会由界面明确提示。
		return true
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		v, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			return false
		}
		return v&capNetBindService != 0
	}
	return false
}
