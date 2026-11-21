package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fngate/api"
	"fngate/cert"
	"fngate/core"
)

//go:embed static
var staticFS embed.FS

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Printf("fnGate %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
			return
		case "--check-bind":
			if core.CanBindLowPort() {
				fmt.Println("ok")
				return
			}
			fmt.Fprintln(os.Stderr, "no cap_net_bind_service")
			os.Exit(1)
		case "--probe-socket":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: fngate --probe-socket <path>")
				os.Exit(2)
			}
			if err := probeSocket(os.Args[2]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("ok")
			return
		case "--cert-sync":
			// root 侧 helper：只读取启动配置里固定的系统证书索引，
			// 复制成应用私有快照后退出。绝不接收任意文件路径参数。
			fs := flag.NewFlagSet("cert-sync", flag.ContinueOnError)
			dataFlag := fs.String("data", "", "data directory")
			if err := fs.Parse(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "参数错误:", err)
				os.Exit(2)
			}
			cfg := LoadConfig(*dataFlag, 0)
			res, err := cert.SyncSystem(cert.SyncOptions{
				DataDir: cfg.DataDir, CertsDir: cfg.CertsDir, SecretsDir: cfg.SecretsDir,
				ConfPaths: cfg.SysConfPaths, SSLRoots: cfg.SysSSLRoots,
				AllowedRoots: cfg.SysAllowed, ChownUser: os.Getenv("FNGATE_APP_USER"),
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "同步飞牛证书失败:", err)
				os.Exit(1)
			}
			fmt.Printf("ok found=%d written=%d skipped=%d sources=%v\n", res.Found, res.Written, res.Skipped, res.Sources)
			for _, w := range res.Warnings {
				fmt.Fprintln(os.Stderr, "warn:", w)
			}
			return
		}
	}

	dataFlag := flag.String("data", "", "data directory (overrides env)")
	webPortFlag := flag.Int("web-port", 0, "web UI port for local debug")
	flag.Parse()

	cfg := LoadConfig(*dataFlag, *webPortFlag)
	logger, err := core.NewLogger(cfg.DataDir, cfg.LogLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法初始化日志:", err)
		os.Exit(1)
	}
	defer logger.Close()

	bus := core.NewEventBus()
	scheduler := core.NewScheduler()
	store, err := core.NewStore(cfg.StateFile, cfg.SecretsDir, bus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法初始化配置:", err)
		os.Exit(1)
	}

	logger.Info("fnGate %s 启动 data=%s socket=%s prefix=%s user=%s can_bind_low=%v",
		version, cfg.DataDir, cfg.SocketPath, cfg.GatewayPrefix, core.RuntimeUser(), core.CanBindLowPort())

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		logger.Error("内嵌前端不可用: %v", err)
		os.Exit(1)
	}
	svc := &api.Services{
		Store: store, Bus: bus, Logger: logger, Scheduler: scheduler,
		Version: version, StartedAt: time.Now(),
	}
	srv := api.New(svc, sub)
	srv.SetGatewayPrefix(cfg.GatewayPrefix)

	deps := &Deps{Cfg: cfg, Store: store, Bus: bus, Logger: logger, Scheduler: scheduler, Version: version}
	mountModules(srv, deps)

	scheduler.Start()
	defer scheduler.Stop()
	bus.Publish("system", "info", "fnGate %s 已启动", version)

	handler := withGatewayPrefix(srv.Handler(), cfg.GatewayPrefix)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)

	if cfg.SocketPath != "" {
		_ = os.Remove(cfg.SocketPath)
		ln, err := net.Listen("unix", cfg.SocketPath)
		if err != nil {
			logger.Error("统一网关 Socket 监听失败: %v", err)
			os.Exit(1)
		}
		_ = os.Chmod(cfg.SocketPath, 0o666)
		logger.Info("统一网关 Socket 已就绪: %s", cfg.SocketPath)
		go func() {
			if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	} else {
		addr := fmt.Sprintf("%s:%d", cfg.WebHost, cfg.WebPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			logger.Error("本地调试监听失败: %v", err)
			os.Exit(1)
		}
		logger.Info("本地调试 HTTP 监听 %s", addr)
		go func() {
			if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		logger.Error("服务异常退出: %v", err)
	case <-ctx.Done():
		logger.Info("收到退出信号，正在关闭")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	if cfg.SocketPath != "" {
		_ = os.Remove(cfg.SocketPath)
	}
	closeModules(deps)
	logger.Info("fnGate 已退出")
}

func withGatewayPrefix(next http.Handler, prefix string) http.Handler {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == prefix {
			target := prefix + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		if strings.HasPrefix(path, prefix+"/") {
			r2 := r.Clone(r.Context())
			r2.URL.Path = strings.TrimPrefix(path, prefix)
			next.ServeHTTP(w, r2)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func probeSocket(path string) error {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("unix", path)
	if err != nil {
		return fmt.Errorf("无法连接 Socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(conn, "GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("健康检查无响应: %w", err)
	}
	if !strings.Contains(string(buf[:n]), "200") {
		return fmt.Errorf("健康检查未返回 200: %s", strings.SplitN(string(buf[:n]), "\r\n", 2)[0])
	}
	return nil
}
