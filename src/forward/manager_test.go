package forward

import (
	"path/filepath"
	"testing"

	"fngate/core"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	bus := core.NewEventBus()
	log, err := core.NewLogger(dir, "ERROR")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	st, err := core.NewStore(filepath.Join(dir, "state.json"), filepath.Join(dir, "secrets"), bus)
	if err != nil {
		t.Fatal(err)
	}
	return New(st, bus, log, core.NewScheduler())
}

func TestValidateMapping(t *testing.T) {
	m := newTestManager(t)
	valid := AddPayload{Protocol: "tcp", ExternalPort: 8443, InternalPort: 443, InternalClient: "192.168.1.10"}
	f, err := m.validate(valid)
	if err != nil {
		t.Fatalf("合法入参被拒绝: %v", err)
	}
	if f.Protocol != "TCP" || f.InternalClient != "192.168.1.10" {
		t.Fatalf("归一化失败: %+v", f)
	}
	cases := []struct {
		name string
		p    AddPayload
	}{
		{"协议非法", AddPayload{Protocol: "SCTP", ExternalPort: 80, InternalPort: 80, InternalClient: "192.168.1.10"}},
		{"外部端口越界", AddPayload{Protocol: "TCP", ExternalPort: 70000, InternalPort: 80, InternalClient: "192.168.1.10"}},
		{"内部端口为 0", AddPayload{Protocol: "TCP", ExternalPort: 80, InternalPort: 0, InternalClient: "192.168.1.10"}},
		{"内部 IP 非法", AddPayload{Protocol: "TCP", ExternalPort: 80, InternalPort: 80, InternalClient: "not-an-ip"}},
		{"负租期", AddPayload{Protocol: "TCP", ExternalPort: 80, InternalPort: 80, InternalClient: "192.168.1.10", LeaseTime: -1}},
	}
	for _, c := range cases {
		if _, err := m.validate(c.p); err == nil {
			t.Errorf("%s 应被拒绝", c.name)
		}
	}
}

func TestSameMapping(t *testing.T) {
	f := core.Forward{Protocol: "TCP", ExternalPort: 8443, InternalPort: 443, InternalClient: "192.168.1.10"}
	p := PortMapping{Protocol: "TCP", ExternalPort: 8443, InternalPort: 443, InternalClient: "192.168.1.10", Enabled: true}
	if !sameMapping(f, p) {
		t.Fatal("相同映射应判定为一致")
	}
	p.InternalPort = 444
	if sameMapping(f, p) {
		t.Fatal("内部端口不同不应判定为一致")
	}
}
