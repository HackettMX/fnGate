package acme

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// 有 CNAME 时必须跟到目标名，否则 TXT 写在带 CNAME 的名字上会被解析器忽略。
func TestResolveChallengeNameFollowsCNAME(t *testing.T) {
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeCNAME {
			switch q.Name {
			case "_acme-challenge.666086.xyz.":
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 600},
					Target: "666086.xyz.",
				})
			case "hop.example.com.":
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 600},
					Target: "hop2.example.com.",
				})
			}
		}
		_ = w.WriteMsg(m)
	}))

	ts := resolveChallengeName("*.666086.xyz", []string{addr})
	if !ts.Followed() {
		t.Fatalf("应识别出 CNAME，实际 query=%q target=%q", ts.Query, ts.Target)
	}
	if ts.Query != "_acme-challenge.666086.xyz" || ts.Target != "666086.xyz" {
		t.Fatalf("解析结果不对：query=%q target=%q", ts.Query, ts.Target)
	}
	if got := ts.Describe(); got != "_acme-challenge.666086.xyz → 666086.xyz" {
		t.Fatalf("说明文案不对：%q", got)
	}

	// 没有 CNAME 时目标名等于查询名。
	plain := resolveChallengeName("example.com", []string{addr})
	if plain.Followed() || plain.Target != "_acme-challenge.example.com" {
		t.Fatalf("无 CNAME 时不应改写：%+v", plain)
	}
}

// 只要有一台 DNS 返回「NOERROR 但没有 CNAME」，不能就此认定没有 CNAME——
// 被劫持或精简的本地 DNS 正是这样把 lego 带偏的。
func TestResolveChallengeNameSkipsSilentServer(t *testing.T) {
	silent := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r) // NOERROR，但什么都不返回
		_ = w.WriteMsg(m)
	}))
	honest := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeCNAME && q.Name == "_acme-challenge.example.com." {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "example.com.",
			})
		}
		_ = w.WriteMsg(m)
	}))

	ts := resolveChallengeName("example.com", []string{silent, honest})
	if ts.Target != "example.com" {
		t.Fatalf("应跳过沉默的 DNS 继续找，实际 target=%q", ts.Target)
	}
}

// CA 视角检查：值在就通过，值不在要说明原因。
func TestTxtVisible(t *testing.T) {
	const want = "qYHIai2p2MUkPUMA_VfxX2n6POdNJPM9sujUrw8P0mU"
	addr := startTestDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeTXT && q.Name == "_acme-challenge.example.com." {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{want},
			})
		}
		_ = w.WriteMsg(m)
	}))

	if ok, detail := txtVisible([]string{addr}, "_acme-challenge.example.com", want); !ok {
		t.Fatalf("应能看到记录，detail=%s", detail)
	}
	if ok, detail := txtVisible([]string{addr}, "_acme-challenge.example.com", "another-value"); ok {
		t.Fatal("值不一致时不应判为可见")
	} else if detail == "" {
		t.Fatal("应给出不一致的原因")
	}
}

func TestLooksLikeACMEValue(t *testing.T) {
	cases := map[string]bool{
		"qYHIai2p2MUkPUMA_VfxX2n6POdNJPM9sujUrw8P0mU":   true,
		`"qYHIai2p2MUkPUMA_VfxX2n6POdNJPM9sujUrw8P0mU"`: true,
		"v=spf1 include:_spf.example.com ~all":          false,
		"short":                                         false,
		"qYHIai2p2MUkPUMA_VfxX2n6POdNJPM9sujUrw8P0m!":   false, // 非 base64url 字符
	}
	for in, want := range cases {
		if got := looksLikeACMEValue(in); got != want {
			t.Fatalf("%q → %v，期望 %v", in, got, want)
		}
	}
}

// 端到端：_acme-challenge 有 CNAME 时，TXT 必须写到根域（sub_domain=@）；
// 同时在查询名上留一份，兼容 lego 按 EffectiveFQDN 做的传播检查。
func TestDNSPodPresentWritesAtCNAMETarget(t *testing.T) {
	created := map[string]string{}

	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/Domain.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":987654,"name":"666086.xyz","status":"enable"}]}`)
		case "/Record.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"records":[]}`)
		case "/Record.Create":
			created[r.Form.Get("sub_domain")] = r.Form.Get("value")
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"record":{"id":"333"}}`)
		default:
			t.Errorf("意外请求：%s", r.URL.Path)
		}
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	p.visibleWait = -1
	p.lookupCNAME = func(name string) string {
		if name == "_acme-challenge.666086.xyz" {
			return "666086.xyz"
		}
		return ""
	}

	if err := p.Present("*.666086.xyz", "tok", "key-auth-cname"); err != nil {
		t.Fatal(err)
	}
	if created["@"] == "" {
		t.Fatalf("TXT 必须写到根域（sub_domain=@），实际创建 %v", created)
	}
	if created["_acme-challenge"] != created["@"] {
		t.Fatalf("查询名上应留一份相同的值，实际 %v", created)
	}
}

// 本次线上故障的回归：CNAME 结论必须来自服务商记录接口。
// 即使本机 DNS 全挂（NAS 上的 fake-ip 代理就是这样），也要跟到目标名。
func TestTargetOfUsesProviderRecordsWhenDNSIsUnusable(t *testing.T) {
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/Domain.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":987654,"name":"666086.xyz","status":"enable"}]}`)
		case "/Record.List":
			if r.Form.Get("record_type") != "CNAME" {
				_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"records":[]}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"records":[
				{"id":"5","name":"*","type":"CNAME","value":"666086.xyz."}
			]}`)
		default:
			t.Errorf("意外请求：%s", r.URL.Path)
		}
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	// 指向一个必然不可用的 DNS：旧实现会因此判定「没有 CNAME」。
	p.resolvers = []string{"127.0.0.1:1"}

	ts := p.targetOf("*.666086.xyz")
	if !ts.Followed() {
		t.Fatalf("应通过服务商记录识别出 CNAME，实际 query=%q target=%q", ts.Query, ts.Target)
	}
	if ts.Target != "666086.xyz" {
		t.Fatalf("CNAME 目标应为根域，实际 %q", ts.Target)
	}
	if got := ts.Describe(); got != "_acme-challenge.666086.xyz → 666086.xyz" {
		t.Fatalf("说明文案不对：%q", got)
	}
}

func TestMatchCNAMERecord(t *testing.T) {
	recs := []dnspodRecord{
		{ID: "1", Name: "*", Type: "CNAME", Value: "666086.xyz"},
		{ID: "2", Name: "www", Type: "CNAME", Value: "cdn.example.net"},
		{ID: "3", Name: "cdn", Type: "CNAME", Value: "other.example.net"},
		{ID: "4", Name: "@", Type: "TXT", Value: "v=spf1 -all"},
	}
	cases := []struct {
		fqdn   string
		want   string
		expect bool
	}{
		// 通配只能覆盖一层
		{"_acme-challenge.666086.xyz", "666086.xyz", true},
		{"a.b.666086.xyz", "", false},
		// 精确记录优先于 * 通配
		{"www.666086.xyz", "cdn.example.net", true},
		{"host.666086.xyz", "666086.xyz", true},
		// * 不覆盖根域自身
		{"666086.xyz", "", false},
	}
	for _, c := range cases {
		got, ok := matchCNAMERecord(recs, "666086.xyz", c.fqdn)
		if ok != c.expect || (ok && got != c.want) {
			t.Errorf("matchCNAMERecord(%q) = %q,%v，期望 %q,%v", c.fqdn, got, ok, c.want, c.expect)
		}
	}
}

// CleanUp 要把两个名字上都清掉，否则会留下永远不被读取的垃圾记录。
func TestDNSPodCleanUpRemovesBothNames(t *testing.T) {
	const keyAuth = "key-auth-cname"
	value := dns01.GetChallengeInfo("*.666086.xyz", keyAuth).Value
	removed := make([]string, 0, 2)

	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/Domain.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":987654,"name":"666086.xyz","status":"enable"}]}`)
		case "/Record.List":
			if r.Form.Get("record_type") == "CNAME" {
				_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"records":[{"id":"5","name":"*","type":"CNAME","value":"666086.xyz"}]}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"status":{"code":"1","message":""},"records":[{"id":"%s","name":"x","type":"TXT","value":"%s"}]}`,
				r.Form.Get("sub_domain"), value)
		case "/Record.Remove":
			removed = append(removed, r.Form.Get("record_id"))
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""}}`)
		default:
			t.Errorf("意外请求：%s", r.URL.Path)
		}
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	if err := p.CleanUp("*.666086.xyz", "tok", "key-auth-cname"); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("根域与查询名上的记录都要清理，实际删除 %v", removed)
	}
}

// 包装层必须把 Preflight 透传出去，否则预检被静默跳过（回归用例）。
type fakePreflightProvider struct{ called bool }

func (f *fakePreflightProvider) Present(string, string, string) error { return nil }
func (f *fakePreflightProvider) CleanUp(string, string, string) error { return nil }
func (f *fakePreflightProvider) Preflight([]string) (string, error) {
	f.called = true
	return "example.com（zone 1）", nil
}

type fakePlainProvider struct{}

func (f *fakePlainProvider) Present(string, string, string) error { return nil }
func (f *fakePlainProvider) CleanUp(string, string, string) error { return nil }

func TestProviderWithTimeoutForwardsPreflight(t *testing.T) {
	inner := &fakePreflightProvider{}
	wrapped := &providerWithTimeout{Provider: inner, timeout: time.Second, interval: time.Second}
	pf, ok := interface{}(wrapped).(preflighter)
	if !ok {
		t.Fatal("包装后必须仍能被识别为支持预检")
	}
	zones, err := pf.Preflight([]string{"example.com"})
	if err != nil || zones == "" || !inner.called {
		t.Fatalf("预检未被透传：zones=%q err=%v called=%v", zones, err, inner.called)
	}

	// 不支持预检的 provider 不应报错，交给上层当作「无信息」。
	plain := &providerWithTimeout{Provider: &fakePlainProvider{}, timeout: time.Second}
	if zones, err := plain.Preflight([]string{"example.com"}); err != nil || zones != "" {
		t.Fatalf("无预检能力时应返回空值，实际 zones=%q err=%v", zones, err)
	}
}
