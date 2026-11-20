package deployer

import (
	"crypto/rand"
	"os"
)

// Engine 持有一份部署状态。所有修改通过互斥锁串行化（busy 语义）。
type Engine struct {
	CertRoot   string
	IndexPath  string
	GatewayPath string
	StateDir   string
	Secure     bool

	busy           bool
	recoveryFailed bool
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
