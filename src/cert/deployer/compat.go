package deployer

import (
	"crypto/rand"
	"os"
	"time"
)

// Engine 持有一份部署状态。所有修改通过互斥锁串行化（busy 语义）。
type Engine struct {
	CertRoot    string
	IndexPath   string
	GatewayPath string
	StateDir    string
	Secure      bool

	busy           bool
	busyStage      string
	busySince      time.Time
	recoveryFailed bool
	// recoveryErr 是上次启动时崩溃恢复失败的原因。守护不会因此退出
	// （退出后主应用只能看到「部署服务未连接」，反而更无从排查），
	// 而是把它交给 /status，由界面说明发生了什么、并允许一键修复。
	recoveryErr string
}

// NewEngine 创建默认引擎（生产路径）。
func NewEngine() *Engine {
	return &Engine{
		CertRoot: CertRoot, IndexPath: IndexPath, GatewayPath: GatewayPath,
		StateDir: StateDir, Secure: true,
	}
}

// fileSnapshot 是回滚日志里的一个文件快照。
type fileSnapshot struct {
	File     string      `json:"file"`
	Content  string      `json:"content"` // base64
	Mode     os.FileMode `json:"mode"`
	UID      int         `json:"uid"`
	GID      int         `json:"gid"`
	IsCert   bool        `json:"is_cert"`
	Next     string      `json:"next,omitempty"` // 部署后的新内容 base64
	NextMode os.FileMode `json:"next_mode,omitempty"`
	NextGID  int         `json:"next_gid,omitempty"`
}

func randRead(b []byte) (int, error) { return rand.Read(b) }
