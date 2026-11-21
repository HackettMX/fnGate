package main

import (
	"fngate/acme"
	"fngate/api"
	"fngate/cert"
	"fngate/core"
	"fngate/forward"
	"fngate/proxy"
)

// Deps 是各业务模块共享的运行时依赖。
type Deps struct {
	Cfg          Config
	Store        *core.Store
	Bus          *core.EventBus
	Logger       *core.Logger
	Scheduler    *core.Scheduler
	Version      string
	ProxyManager *proxy.Manager
	CertManager  *cert.Manager
	ACMEManager  *acme.Manager
}

// mountModules 按里程碑逐步填充；每个模块自行读取 State，互不直接依赖。
func mountModules(s *api.Server, d *Deps) {
	fwd := forward.New(d.Store, d.Bus, d.Logger, d.Scheduler)
	s.Mount("forward", forward.NewModule(fwd))

	px := proxy.New(d.Store, d.Bus, d.Logger, d.Scheduler, d.Cfg.CertsDir)
	d.ProxyManager = px

	cm := cert.New(cert.Options{
		DataDir: d.Cfg.DataDir, CertsDir: d.Cfg.CertsDir, SecretsDir: d.Cfg.SecretsDir,
		SysConfPaths: d.Cfg.SysConfPaths, SysSSLRoots: d.Cfg.SysSSLRoots,
		SysAllowedRoots: d.Cfg.SysAllowed,
		Store:           d.Store, Bus: d.Bus, Logger: d.Logger,
	})
	d.CertManager = cm
	s.Mount("cert", cert.NewModule(cm))

	// 证书模块实现 proxy.CertResolver（结构化接口），注入后 HTTPS 握手
	// 每次都会向证书库查询，续期落盘后无需重建监听即可生效。
	px.SetCertResolver(cm)
	if _, err := cm.ImportFromSnapshot(); err != nil {
		d.Logger.Warn("导入飞牛证书快照失败: %v", err)
	}

	am := acme.New(acme.Deps{
		Store: d.Store, Bus: d.Bus, Logger: d.Logger,
		Scheduler: d.Scheduler, Certs: cm,
	})
	d.ACMEManager = am
	s.Mount("acme", acme.NewModule(am))
	// DNS 服务商从 ACME 里拆出来，前端是独立页面、后端是独立路由前缀。
	s.Mount("dns", acme.NewDNSModule(am))

	s.Mount("proxy", proxy.NewModule(px, d.Store))
	px.Apply()
}

func closeModules(d *Deps) {
	if d.ACMEManager != nil {
		d.ACMEManager.Close()
	}
	if d.ProxyManager != nil {
		d.ProxyManager.Close()
	}
}
