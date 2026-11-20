package deployer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Server 是 root 侧受限的部署服务，只监听本地 Unix Socket。
type Server struct {
	engine   *Engine
	socket   string
	runDir   string
	groupGID int
	httpSrv  *http.Server
	ln       net.Listener
}

// NewServer 创建服务。groupGID 为应用用户组 GID，用于 socket 0660 授权主应用连接。
func NewServer(socket, runDir string, groupGID int) *Server {
	return &Server{
		engine: NewEngine(), socket: socket, runDir: runDir, groupGID: groupGID,
	}
}

// Start 校验运行环境、执行崩溃恢复、开始监听。阻塞直到 Stop/错误。
func (s *Server) Start() error {
	if os.Geteuid() != 0 {
		return errors.New("cert-deployer requires root")
	}
	// 校验 runDir：目录存在、属主 root、不可被 group/other 写。
	st, err := os.Lstat(s.runDir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !ownedByRootNotWritable(st) {
		return errors.New("unsafe helper run directory")
	}
	// 启动时先做崩溃恢复。
	if err := s.engine.Recover(); err != nil {
		return err
	}
	// 清理旧 socket（必须是 root 的 socket 文件）。
	if old, err := os.Lstat(s.socket); err == nil {
		if old.Mode()&os.ModeSocket == 0 || ownerUID(old) != 0 {
			return errors.New("unsafe helper socket")
		}
		_ = os.Remove(s.socket)
	}
	ln, err := net.Listen("unix", s.socket)
	if err != nil {
		return err
	}
	s.ln = ln
	// chown root:group + chmod 0660：仅 root 与应用组可连。
	if err := os.Chown(s.socket, 0, s.groupGID); err != nil {
		_ = ln.Close()
		return err
	}
	if err := os.Chmod(s.socket, 0o660); err != nil {
		_ = ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/prepare", s.handlePrepare)
	mux.HandleFunc("/deploy", s.handleDeploy)
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
	}
	return s.httpSrv.Serve(ln)
}

// Stop 优雅关闭服务。
func (s *Server) Stop() error {
	if s.httpSrv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) running() bool {
	busy, _, _ := s.engine.runningInfo()
	return busy
}

func (s *Server) decode(r *http.Request, dst interface{}) error {
	if r.Method != http.MethodPost {
		return errors.New("method")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func (s *Server) reply(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) replyErr(w http.ResponseWriter, err error) {
	de := &DeployError{}
	if errors.As(err, &de) {
		body := map[string]interface{}{
			"code": string(de.Code), "stage": de.Stage, "error": Text(de.Code),
		}
		if de.Detail != "" {
			body["detail"] = de.Detail
			body["error"] = Text(de.Code) + "：" + de.Detail
		}
		s.reply(w, statusOf(err), body)
		return
	}
	s.reply(w, 503, map[string]interface{}{
		"code": string(CodeIncompatible), "error": Text(CodeIncompatible),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	res, err := s.engine.Status()
	if err != nil {
		s.replyErr(w, err)
		return
	}
	s.reply(w, 200, res)
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	var in PrepareInput
	if err := s.decode(r, &in); err != nil {
		s.reply(w, 400, map[string]interface{}{"code": string(CodeInvalid), "error": Text(CodeInvalid)})
		return
	}
	res, err := s.engine.Prepare(in, s.running())
	if err != nil {
		s.replyErr(w, err)
		return
	}
	s.reply(w, 200, res)
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var in PrepareInput
	if err := s.decode(r, &in); err != nil {
		s.reply(w, 400, map[string]interface{}{"code": string(CodeInvalid), "error": Text(CodeInvalid)})
		return
	}
	res, err := s.engine.Deploy(in, s.running())
	if err != nil {
		s.replyErr(w, err)
		return
	}
	s.reply(w, 200, res)
}
