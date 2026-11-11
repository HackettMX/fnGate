package acme

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestNormalizeQueryName(t *testing.T) {
	ok := map[string]string{
		"example.com":                      "example.com",
		"  EXAMPLE.com. ":                  "example.com",
		"https://666086.xyz/app?x=1":       "666086.xyz",
		"*.example.com":                    "example.com",
		"_acme-challenge.666086.xyz":       "_acme-challenge.666086.xyz",
		"user@example.com":                 "example.com",
		"http://a.b.example.com:8080/path": "a.b.example.com:8080", // 端口不属于域名，交给 DNS 查询失败
	}
	for in, want := range ok {
		got, err := normalizeQueryName(in)
		if in == "http://a.b.example.com:8080/path" {
			// 带端口会被判为非法字符，属于预期拒绝。
			if err == nil {
				t.Fatalf("%q 含端口应被拒绝，实际 %q", in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q 应被接受：%v", in, err)
		}
		if got != want {
			t.Fatalf("%q → %q，期望 %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "   ", "localhost", "exa mple.com", "例子.中国"} {
		if _, err := normalizeQueryName(bad); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
}

func TestResolveQType(t *testing.T) {
	if q, err := resolveQType("txt"); err != nil || q != dns.TypeTXT {
		t.Fatalf("TXT 解析失败：%v %v", q, err)
	}
	if _, err := resolveQType("SPF"); err == nil {
		t.Fatal("不支持的记录类型应报错")
	}
}

// 两台服务器给出不同答案时必须判为不一致，并各自保留原始回答。
func TestResolveQueryDetectsInconsistency(t *testing.T) {
	a1 := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("1.1.1.1"),
			})
		}
		_ = w.WriteMsg(m)
	}))
	a2 := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("2.2.2.2"),
			})
		}
		_ = w.WriteMsg(m)
	}))

	res, err := runResolveQuery("example.com", "A", []string{a1, a2}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("应保留两台服务器的结果，实际 %d", len(res.Results))
	}
	if res.Consistent {
		t.Fatal("两台答案不同应判为不一致")
	}
	if !strings.Contains(res.Summary, "不一致") {
		t.Fatalf("结论描述不清晰：%q", res.Summary)
	}
}

// 回答里只有 CNAME 时，跟随开关应补查链尾并合并最终答案。
func TestResolveQueryFollowsCNAME(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case strings.EqualFold(q.Name, "www.example.com.") && q.Qtype == dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "target.example.net.",
			})
		case strings.EqualFold(q.Name, "target.example.net.") && q.Qtype == dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"hello"},
			})
		}
		_ = w.WriteMsg(m)
	}))

	res, err := runResolveQuery("www.example.com", "TXT", []string{addr}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalName != "target.example.net" {
		t.Fatalf("链尾应为 target.example.net，实际 %q（chain=%v）", res.FinalName, res.Chain)
	}
	joined := strings.Join(res.Results[0].Answers, "\n")
	if !strings.Contains(joined, "hello") {
		t.Fatalf("跟随 CNAME 后应包含最终 TXT，实际 %q", joined)
	}
}

// 关闭跟随时只保留原始回答，方便看清 CNAME 走到哪一步。
func TestResolveQueryWithoutFollow(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case strings.EqualFold(q.Name, "www.example.com."):
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "target.example.net.",
			})
		case strings.EqualFold(q.Name, "target.example.net."):
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"hello"},
			})
		}
		_ = w.WriteMsg(m)
	}))

	res, err := runResolveQuery("www.example.com", "TXT", []string{addr}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(res.Results[0].Answers, "\n"), "hello") {
		t.Fatal("关闭跟随后不应出现最终 TXT")
	}
	if len(res.Chain) == 0 {
		t.Fatal("即使不跟随，也应展示 CNAME 链")
	}
}

// newZoneDNS 模拟一套正常委派的 DNS：apex NS 有 Answer、SOA 正常、_acme-challenge 干净。
func newZoneDNS(t *testing.T, apexNSAnswer bool) (string, string) {
	t.Helper()
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		switch q.Qtype {
		case dns.TypeSOA:
			if name == "example.com." {
				m.Answer = append(m.Answer, soaRR("example.com", "ns1.example.net"))
			}
		case dns.TypeNS:
			if name != "example.com." {
				break
			}
			if apexNSAnswer {
				m.Answer = append(m.Answer, nsRR("example.com", "ns1.example.net"), nsRR("example.com", "ns2.example.net"))
			} else {
				// DNSPod 行为：Answer 为空，只有 authority 段 SOA。
				m.Ns = append(m.Ns, soaRR("example.com", "ns1.example.net"))
			}
		case dns.TypeA:
			switch name {
			case "ns1.example.net.", "ns2.example.net.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("10.0.0.1"),
				})
			case "example.com.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("5.6.7.8"),
				})
			}
		}
		_ = w.WriteMsg(m)
	}))
	return addr, addr
}

func TestDiagnoseHealthyDomain(t *testing.T) {
	addr, _ := newZoneDNS(t, true)
	res, err := runDiagnose("example.com", []string{addr, addr})
	if err != nil {
		t.Fatal(err)
	}
	if res.Zone != "example.com" {
		t.Fatalf("zone 应为 example.com，实际 %q", res.Zone)
	}
	if res.FailCount != 0 || res.WarnCount != 0 {
		t.Fatalf("正常域名不应有警告/失败：%+v", res.Checks)
	}
	if len(res.Checks) != 6 {
		t.Fatalf("应返回 6 条检查，实际 %d", len(res.Checks))
	}
	if !strings.Contains(res.Verdict, "全部通过") {
		t.Fatalf("结论不正确：%q", res.Verdict)
	}
}

// 复现 666086.xyz 的两个坑：apex NS 空答案 + _acme-challenge 被 CNAME 到根域。
func TestDiagnoseDNSPodStyleZone(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		switch q.Qtype {
		case dns.TypeSOA:
			if name == "example.com." {
				m.Answer = append(m.Answer, soaRR("example.com", "f1g1ns1.dnspod.net"))
			}
		case dns.TypeNS:
			if name == "example.com." {
				m.Ns = append(m.Ns, soaRR("example.com", "f1g1ns1.dnspod.net"))
			}
		case dns.TypeA:
			switch name {
			case "f1g1ns1.dnspod.net.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("1.2.3.4"),
				})
			case "example.com.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("5.6.7.8"),
				})
			}
		case dns.TypeCNAME:
			// 通配 CNAME：_acme-challenge 被带到根域
			if name == "_acme-challenge.example.com." {
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: "example.com.",
				})
			}
		}
		_ = w.WriteMsg(m)
	}))

	res, err := runDiagnose("example.com", []string{addr, addr})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]checkItem{}
	for _, c := range res.Checks {
		byID[c.ID] = c
	}
	if c := byID["apex_ns_answer"]; c.Status != checkWarn || !strings.Contains(c.Advice, "降级") {
		t.Fatalf("apex NS 空答案应给出降级建议，实际 %+v", c)
	}
	if c := byID["acme_challenge"]; c.Status != checkWarn || !strings.Contains(c.Detail, "CNAME") {
		t.Fatalf("_acme-challenge 被 CNAME 应给出警告，实际 %+v", c)
	}
	if c := byID["ns_delegation"]; c.Status != checkWarn {
		t.Fatalf("只能从 SOA 得到 NS 时应为提醒，实际 %+v", c)
	}
	if res.FailCount != 0 {
		t.Fatalf("这两类问题不阻断签发，不应判为失败：%+v", res.Checks)
	}
	if !strings.Contains(res.Verdict, "可以签发") {
		t.Fatalf("结论不正确：%q", res.Verdict)
	}
}

// 区域完全查不到时，其余检查应标记为跳过而不是全部报错。
func TestDiagnoseUnknownZoneSkipsRest(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	}))
	res, err := runDiagnose("nonexistent-zone-xyz.com", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if res.FailCount != 1 {
		t.Fatalf("应只有 NS 委派一条失败，实际 %+v", res.Checks)
	}
	for _, c := range res.Checks[1:] {
		if c.Status != checkSkip {
			t.Fatalf("%s 应跳过，实际 %s", c.ID, c.Status)
		}
	}
}

func TestIsHijackedIP(t *testing.T) {
	cases := map[string]bool{
		"198.18.1.105": true,
		"198.19.0.1":   true,
		"0.0.0.0":      true,
		"223.5.5.5":    false,
		"198.168.1.1":  false,
		"2606:4700::1": false,
	}
	for in, want := range cases {
		if got := isHijackedIP(net.ParseIP(in)); got != want {
			t.Fatalf("%s → %v，期望 %v", in, got, want)
		}
	}
}

// 权威 NS 被代理软件 fake-ip 劫持时，要明确指出是假的 IP 而不是「解析正常」。
func TestDiagnoseWarnsOnFakeIP(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		switch q.Qtype {
		case dns.TypeSOA:
			if name == "example.com." {
				m.Answer = append(m.Answer, soaRR("example.com", "ns1.example.net"))
			}
		case dns.TypeNS:
			if name == "example.com." {
				m.Answer = append(m.Answer, nsRR("example.com", "ns1.example.net"))
			}
		case dns.TypeA:
			ip := "5.6.7.8"
			if name == "ns1.example.net." {
				ip = "198.18.1.105" // fake-ip
			}
			if name == "ns1.example.net." || name == "example.com." {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(ip),
				})
			}
		}
		_ = w.WriteMsg(m)
	}))

	res, err := runDiagnose("example.com", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Checks {
		if c.ID != "ns_resolvable" {
			continue
		}
		if c.Status != checkWarn {
			t.Fatalf("fake-ip 应给出提醒，实际 %+v", c)
		}
		if !strings.Contains(c.Advice, "fake-ip") {
			t.Fatalf("建议应点明 fake-ip，实际 %q", c.Advice)
		}
		return
	}
	t.Fatal("缺少 ns_resolvable 检查项")
}
