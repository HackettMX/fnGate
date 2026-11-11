package acme

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// startTestDNS 起一个本地 UDP DNS 服务器，返回其地址。
func startTestDNS(t *testing.T, h dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地 UDP 失败：%v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func soaRR(zone, mname string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 180},
		Ns:      dns.Fqdn(mname),
		Mbox:    "freednsadmin.dnspod.com.",
		Serial:  1,
		Refresh: 3600, Retry: 180, Expire: 1209600, Minttl: 180,
	}
}

func nsRR(zone, host string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600},
		Ns:  dns.Fqdn(host),
	}
}

// DNSPod 免费版的行为：apex 的 NS 查询返回 NOERROR 但 Answer 为空，只有 authority 段 SOA。
func TestApexNameserversFallsBackToSOA(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeNS:
			// 故意留空 Answer，只在 authority 段放 SOA（真实 DNSPod 就是这样）
			m.Ns = append(m.Ns, soaRR("example.com", "f1g1ns1.dnspod.net"))
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soaRR("example.com", "f1g1ns1.dnspod.net"))
		}
		_ = w.WriteMsg(m)
	}))

	ns, source, err := apexNameservers("example.com", []string{addr})
	if err != nil {
		t.Fatalf("应能从 SOA 回退出权威 NS：%v", err)
	}
	if source != "SOA" {
		t.Fatalf("来源应为 SOA，实际 %q", source)
	}
	if len(ns) != 1 || ns[0] != "f1g1ns1.dnspod.net" {
		t.Fatalf("权威 NS 解析不正确：%v", ns)
	}
}

func TestApexNameserversUsesNSWhenPresent(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeNS {
			m.Answer = append(m.Answer, nsRR("example.com", "ns1.example.net"), nsRR("example.com", "ns2.example.net"))
		}
		_ = w.WriteMsg(m)
	}))

	ns, source, err := apexNameservers("example.com", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if source != "NS" || len(ns) != 2 {
		t.Fatalf("应直接使用 NS 记录，实际 source=%q ns=%v", source, ns)
	}
}

func TestFindZoneWalksUp(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeSOA && strings.EqualFold(q.Name, "example.com.") {
			m.Answer = append(m.Answer, soaRR("example.com", "ns1.example.net"))
		}
		_ = w.WriteMsg(m)
	}))

	zone, err := findZone("_acme-challenge.www.example.com", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if zone != "example.com" {
		t.Fatalf("zone 应为 example.com，实际 %q", zone)
	}
}

// auto 模式下遇到「NS 空答案」应自动降级，不再让 lego 空等到超时。
func TestPlanDNSCheckAutoDegrades(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeNS:
			m.Ns = append(m.Ns, soaRR("example.com", "f1g1ns1.dnspod.net"))
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soaRR("example.com", "f1g1ns1.dnspod.net"))
		}
		_ = w.WriteMsg(m)
	}))

	plan, err := planDNSCheck([]string{"example.com", "*.example.com"}, "auto", []string{addr})
	if err != nil {
		t.Fatalf("auto 模式不应报错：%v", err)
	}
	if plan.Mode != dnsCheckRecursive {
		t.Fatalf("应降级为递归校验，实际 %q", plan.Mode)
	}
	if !strings.Contains(plan.Reason, "NS 查询返回空答案") {
		t.Fatalf("降级原因不清晰：%q", plan.Reason)
	}
	if plan.Zone != "example.com" {
		t.Fatalf("zone 不正确：%q", plan.Zone)
	}
}

// 显式选 strict 时，若 NS 查不到应直接给出原因（由上层降级并记日志），而不是静默放行。
func TestPlanDNSCheckStrictReportsMissingNS(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeNS:
			m.Ns = append(m.Ns, soaRR("example.com", "f1g1ns1.dnspod.net"))
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soaRR("example.com", "f1g1ns1.dnspod.net"))
		}
		_ = w.WriteMsg(m)
	}))

	if _, err := planDNSCheck([]string{"example.com"}, "strict", []string{addr}); err == nil {
		t.Fatal("strict 模式遇到 NS 空答案应返回错误，提示改用其他校验方式")
	}
}

// NS 正常时 auto 不应降级。
func TestPlanDNSCheckAutoKeepsStrict(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeNS:
			m.Answer = append(m.Answer, nsRR("example.com", "ns1.example.net"))
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soaRR("example.com", "ns1.example.net"))
		}
		_ = w.WriteMsg(m)
	}))

	plan, err := planDNSCheck([]string{"*.example.com"}, "auto", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != dnsCheckStrict {
		t.Fatalf("NS 正常时应保持严格校验，实际 %q", plan.Mode)
	}
}

// 记录写的名字被 CNAME 带到别处时，要能读出 CNAME 目标，便于日志/诊断。
func TestLookupTXTFollowsCNAME(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer,
				&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "example.com."},
				&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 600}, Txt: []string{"v1"}},
			)
		}
		_ = w.WriteMsg(m)
	}))

	values, cname, err := lookupTXT("_acme-challenge.example.com", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if cname != "example.com" {
		t.Fatalf("CNAME 目标解析不正确：%q", cname)
	}
	if len(values) != 1 || values[0] != "v1" {
		t.Fatalf("TXT 值解析不正确：%v", values)
	}
}
