package cert

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fngate/cert/deployer"
	"fngate/core"
)

// 本文件实现「把应用证书同步到飞牛系统 HTTPS」的业务编排。
// 所有操作单证书维度；系统侧写入由 root 守护（deployer）执行。

// FNOSOverview 是证书列表/页面层面的同步概览。
type FNOSOverview struct {
	Available   bool              `json:"available"`
	DaemonReady bool              `json:"daemon_ready"`
	Targets     []deployer.Target `json:"targets"`
	Unavailable []deployer.Target `json:"unavailable_targets"`
	Certs       []FNOSCertStatus  `json:"certs"`
	Ports       []int             `json:"ports"`
	Diagnostics []string          `json:"diagnostics"`
}

type FNOSCertStatus struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Status        string `json:"status"` // none | deployed | stale | error
	TargetID      string `json:"target_id,omitempty"`
	TargetDomains []string `json:"target_domains,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	LastDeployAt  string `json:"last_deploy_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	AutoDeploy    bool   `json:"auto_deploy"`
}

// FNOSStatus 返回守护状态与每张证书的同步状态。守护离线时仍返回证书状态，
// 只是 Available=false，前端据此提示重启应用。
func (m *Manager) FNOSStatus(ctx context.Context) (*FNOSOverview, error) {
	ov := &FNOSOverview{
		Targets: []deployer.Target{}, Unavailable: []deployer.Target{},
		Certs: []FNOSCertStatus{}, Diagnostics: []string{}, Ports: []int{},
	}
	if m.pushClient.deployAvailable() {
		res, err := m.pushClient.Status(ctx)
		if err == nil {
			ov.Available = true
			ov.DaemonReady = true
			ov.Targets = res.Targets
			ov.Unavailable = res.Unavailable
			ov.Diagnostics = res.Diagnostics
			if len(res.Ports) > 0 {
				ov.Ports = res.Ports
			}
		}
	}
	for _, c := range m.opt.Store.Snapshot().Certificates {
		ov.Certs = append(ov.Certs, fnosCertStatus(c))
	}
	return ov, nil
}

func fnosCertStatus(c core.Certificate) FNOSCertStatus {
	s := FNOSCertStatus{ID: c.ID, Name: c.Name, Status: "none"}
	if c.FNOS == nil {
		return s
	}
	s.TargetID = c.FNOS.TargetID
	s.TargetDomains = c.FNOS.TargetDomains
	s.Fingerprint = c.FNOS.Fingerprint
	s.LastDeployAt = c.FNOS.LastDeployAt
	s.LastError = c.FNOS.LastError
	s.AutoDeploy = c.FNOS.AutoDeploy
	switch c.FNOS.Status {
	case "deployed", "stale", "error":
		s.Status = c.FNOS.Status
	default:
		s.Status = "none"
	}
	return s
}

// fnosInput 从证书库取出证书对，构造部署输入。
func (m *Manager) fnosInput(c core.Certificate, targetID, host string, port int) (deployer.PrepareInput, error) {
	chain, err := m.ReadChain(c)
	if err != nil {
		return deployer.PrepareInput{}, fmt.Errorf("证书链不可读：%w", err)
	}
	key, err := m.ReadKey(c)
	if err != nil {
		return deployer.PrepareInput{}, err
	}
	return deployer.PrepareInput{
		TargetID: targetID, CertificatePEM: string(chain), PrivateKeyPEM: string(key),
		ProbeHost: host, ProbePort: port,
	}, nil
}

// FNOSPrepare 预检一张证书能否替换指定飞牛目标，返回计划（不写入）。
func (m *Manager) FNOSPrepare(ctx context.Context, certID, targetID, host string, port int) (*deployer.PrepareResult, error) {
	c, ok := m.ByID(certID)
	if !ok {
		return nil, fmt.Errorf("证书不存在")
	}
	input, err := m.fnosInput(c, targetID, host, port)
	if err != nil {
		return nil, err
	}
	return m.pushClient.Prepare(ctx, input)
}

// FNOSDeploy 部署一张证书到飞牛系统 HTTPS。成功后记录同步状态。
func (m *Manager) FNOSDeploy(ctx context.Context, certID, targetID, host string, port int, planID string) (*deployer.DeployResult, error) {
	c, ok := m.ByID(certID)
	if !ok {
		return nil, fmt.Errorf("证书不存在")
	}
	input, err := m.fnosInput(c, targetID, host, port)
	if err != nil {
		return nil, err
	}
	input.PlanID = planID
	res, err := m.pushClient.Deploy(ctx, input)
	if err != nil {
		m.setFNOSState(certID, func(meta *core.FNOSMeta) {
			meta.Status = "error"
			meta.LastError = err.Error()
		})
		return nil, err
	}
	// 成功：记录目标、指纹、时间；保留用户已有的 AutoDeploy 设置。
	targetDomains := append([]string(nil), c.SANs...)
	m.setFNOSState(certID, func(meta *core.FNOSMeta) {
		meta.TargetID = targetID
		meta.TargetDomains = targetDomains
		meta.ProbeHost = host
		meta.ProbePort = port
		meta.Fingerprint = c.Fingerprint
		meta.Status = "deployed"
		meta.LastDeployAt = time.Now().Format("2006-01-02 15:04:05")
		meta.LastError = ""
	})
	if m.opt.Bus != nil {
		m.opt.Bus.Publish("cert", "info", "证书「%s」已同步到飞牛系统 HTTPS", c.Name)
	}
	return res, nil
}

// setFNOSState 在原子写中更新证书的 FNOS 元数据。
func (m *Manager) setFNOSState(certID string, fn func(*core.FNOSMeta)) error {
	return m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID != certID {
				continue
			}
			if st.Certificates[i].FNOS == nil {
				st.Certificates[i].FNOS = &core.FNOSMeta{}
			}
			fn(st.Certificates[i].FNOS)
			st.Certificates[i].UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
			return nil
		}
		return fmt.Errorf("证书 %s 不存在", certID)
	})
}

// FNOSSetAuto 开启/关闭「续期后自动重新部署」。必须先成功手动部署一次。
func (m *Manager) FNOSSetAuto(certID string, on bool) error {
	c, ok := m.ByID(certID)
	if !ok {
		return fmt.Errorf("证书不存在")
	}
	if on && (c.FNOS == nil || c.FNOS.Status != "deployed" || c.FNOS.TargetID == "") {
		return fmt.Errorf("请先手动成功部署一次，再开启自动同步")
	}
	return m.setFNOSState(certID, func(meta *core.FNOSMeta) {
		meta.AutoDeploy = on
	})
}

// FNOSReset 清除一张证书的飞牛同步状态（不再自动重新部署）。
func (m *Manager) FNOSReset(certID string) error {
	return m.opt.Store.Update(func(st *core.State) error {
		for i := range st.Certificates {
			if st.Certificates[i].ID == certID {
				st.Certificates[i].FNOS = nil
				return nil
			}
		}
		return fmt.Errorf("证书 %s 不存在", certID)
	})
}

// FNOSRedeployAfterRenew 在 ACME 续期成功后调用：若开启了自动同步且证书指纹已变化，
// 用新证书重新部署到原飞牛目标。部署失败只记录状态，不影响续期主流程。
// 由调用方决定是否在 goroutine 中执行（部署涉及服务重启，可能耗时数十秒）。
func (m *Manager) FNOSRedeployAfterRenew(ctx context.Context, certID string) error {
	c, ok := m.ByID(certID)
	if !ok || c.FNOS == nil {
		return nil
	}
	meta := c.FNOS
	if !meta.AutoDeploy || meta.Status != "deployed" || meta.TargetID == "" {
		return nil
	}
	// 指纹未变说明并非真正换证，无需重新部署。
	if meta.Fingerprint != "" && sameFP(meta.Fingerprint, c.Fingerprint) {
		return nil
	}
	if meta.ProbeHost == "" || meta.ProbePort == 0 {
		return fmt.Errorf("飞牛自动同步缺少验证主机/端口，已跳过")
	}

	// 先 prepare 拿 planID，再 deploy，避免部署时目标已变化。
	prep, err := m.FNOSPrepare(ctx, certID, meta.TargetID, meta.ProbeHost, meta.ProbePort)
	if err != nil {
		m.markFNOSStale(certID, "自动同步预检失败："+err.Error())
		return err
	}
	res, err := m.FNOSDeploy(ctx, certID, meta.TargetID, meta.ProbeHost, meta.ProbePort, prep.PlanID)
	if err != nil {
		m.markFNOSStale(certID, "续期后自动同步失败："+err.Error())
		return err
	}
	if m.opt.Bus != nil {
		m.opt.Bus.Publish("cert", "info", "证书「%s」续期后已自动重新同步到飞牛（%s）", c.Name, res.Fingerprint[:12])
	}
	return nil
}

// markFNOSStale 把同步状态标记为需关注（stale），保留历史目标与指纹。
func (m *Manager) markFNOSStale(certID, reason string) {
	_ = m.setFNOSState(certID, func(meta *core.FNOSMeta) {
		meta.Status = "stale"
		meta.LastError = reason
	})
}

func sameFP(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, ":", ""), strings.ReplaceAll(b, ":", ""))
}
