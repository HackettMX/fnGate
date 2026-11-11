package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatchZoneAndSubDomain(t *testing.T) {
	zones := []dnspodZone{
		{ID: "1", Name: "666086.xyz"},
		{ID: "2", Name: "sub.666086.xyz"},
		{ID: "3", Name: "example.com"},
	}
	cases := []struct {
		fqdn    string
		zone    string
		sub     string
		matched bool
	}{
		{"_acme-challenge.666086.xyz", "666086.xyz", "_acme-challenge", true},
		{"_acme-challenge.666086.xyz.", "666086.xyz", "_acme-challenge", true},
		{"_acme-challenge.SUB.666086.xyz", "sub.666086.xyz", "_acme-challenge", true},
		{"666086.xyz", "666086.xyz", "@", true},
		{"_acme-challenge.other.net", "", "", false},
		// 不能被 "666086.xyz" 这个字符串从中间匹配到
		{"_acme-challenge.not666086.xyz", "", "", false},
	}
	for _, c := range cases {
		z, ok := matchZone(c.fqdn, zones)
		if ok != c.matched {
			t.Fatalf("matchZone(%q) matched=%v，期望 %v", c.fqdn, ok, c.matched)
		}
		if !ok {
			continue
		}
		if z.Name != c.zone {
			t.Fatalf("matchZone(%q)=%q，期望 %q", c.fqdn, z.Name, c.zone)
		}
		if sub := subDomainOf(c.fqdn, z.Name); sub != c.sub {
			t.Fatalf("subDomainOf(%q,%q)=%q，期望 %q", c.fqdn, z.Name, sub, c.sub)
		}
	}
}

func TestNormalizeApex(t *testing.T) {
	cases := map[string]string{
		"*.666086.xyz":   "666086.xyz",
		"666086.xyz.":    "666086.xyz",
		"  *.A.Example ": "a.example",
		"666086.xyz":     "666086.xyz",
	}
	for in, want := range cases {
		if got := normalizeApex(in); got != want {
			t.Fatalf("normalizeApex(%q)=%q，期望 %q", in, got, want)
		}
	}
}

func TestDNSPodErrorHuman(t *testing.T) {
	cases := []struct{ code, msg, want string }{
		{"10004", "Token 验证失败", "API Token"},
		{"10002", "请求频率过高", "频繁"},
		{"-1", "记录已存在", "同名 TXT 记录"},
		{"-4", "域名不存在", "不在当前 DNSPod 账号"},
		{"", "未知的服务端故障", "测试连接"}, // 无匹配建议时也要给出下一步
	}
	for _, c := range cases {
		got := newDNSPodError("写入 TXT 记录", c.code, c.msg).Human()
		if !strings.Contains(got, c.want) {
			t.Errorf("code=%s msg=%s 的提示 %q 不含 %q", c.code, c.msg, got, c.want)
		}
		if c.code != "" && !strings.Contains(got, c.code) {
			t.Errorf("提示里应保留原始错误码 %s：%q", c.code, got)
		}
	}
}

// 这是本次故障的核心诉求：包装层不能把服务商原话吞掉。
func TestHumanizeSurfacesProviderDetail(t *testing.T) {
	raw := "[666086.xyz] acme: error presenting token: API call failed: could not get domains: Token 验证失败"
	got := humanizeACMEErr(errString(raw))
	if !strings.Contains(got, "写入 DNS TXT 记录失败") {
		t.Fatalf("应保留统一前缀：%q", got)
	}
	if !strings.Contains(got, "Token 验证失败") {
		t.Fatalf("必须带出服务商原话，实际：%q", got)
	}
	if strings.Contains(got, "could not get domains") {
		t.Fatalf("不应把中间层包装也塞给用户：%q", got)
	}

	cases := map[string]string{
		"error presenting token": "写入 DNS TXT 记录失败",
		"[x] acme: error presenting token: API call failed: could not get domains: 记录已存在": "记录已存在",
	}
	for in, want := range cases {
		if got := humanizeACMEErr(errString(in)); !strings.Contains(got, want) {
			t.Errorf("humanizeACMEErr(%q)=%q 不含 %q", in, got, want)
		}
	}
}

func newTestDNSPodServer(t *testing.T, handler http.HandlerFunc) (*dnspodAPI, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	api := newDNSPodAPI("12345,abcdef")
	api.endpoint = srv.URL + "/"
	return api, srv.Close
}

func TestDNSPodListZonesPagination(t *testing.T) {
	// 第一页塞满 100 条且不含目标域名，目标域名在第二页——正是 lego 会漏掉的情形。
	var pages int
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Domain.List" {
			t.Errorf("意外请求：%s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("login_token") != "12345,abcdef" {
			t.Errorf("login_token 未正确传递：%q", r.Form.Get("login_token"))
		}
		if ua := r.Header.Get("User-Agent"); ua == "" || ua == "Go-http-client/1.1" {
			t.Errorf("必须带自定义 UA，实际 %q", ua)
		}
		pages++
		var domains []map[string]interface{}
		if r.Form.Get("page") == "1" {
			for i := 0; i < dnspodPageSize; i++ {
				domains = append(domains, map[string]interface{}{"id": 1000 + i, "name": fmt.Sprintf("filler%02d.com", i), "status": "enable"})
			}
		} else {
			domains = append(domains, map[string]interface{}{"id": 987654, "name": "666086.xyz", "status": "enable"})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  map[string]string{"code": "1", "message": ""},
			"domains": domains,
		})
	})
	defer done()

	zones, err := api.listZones()
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 {
		t.Fatalf("应翻到第 2 页，实际请求 %d 次", pages)
	}
	if len(zones) != dnspodPageSize+1 {
		t.Fatalf("应拿到 %d 个域名，实际 %d", dnspodPageSize+1, len(zones))
	}
	z, ok := matchZone("_acme-challenge.666086.xyz", zones)
	if !ok || z.Name != "666086.xyz" || z.ID != "987654" {
		t.Fatalf("第二页的域名应被匹配到：%+v ok=%v", z, ok)
	}
}

func TestDNSPodEmptyRecordListIsNotError(t *testing.T) {
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":{"code":"10","message":"记录列表为空"}}`)
	})
	defer done()
	recs, err := api.listTXT("123", "_acme-challenge")
	if err != nil {
		t.Fatalf("空列表不应报错：%v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("空列表应返回 0 条，实际 %d", len(recs))
	}
}

func TestDNSPodTokenErrorIsHumanized(t *testing.T) {
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":{"code":"10004","message":"Token 验证失败"}}`)
	})
	defer done()
	_, err := api.listZones()
	if err == nil {
		t.Fatal("鉴权失败应返回错误")
	}
	var apiErr *dnspodAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("应返回 *dnspodAPIError，实际 %T", err)
	}
	if apiErr.Code != "10004" {
		t.Fatalf("应保留原始错误码，实际 %q", apiErr.Code)
	}
	// 界面拿到的是 humanize 之后的一句话，必须能看出是 Token 的问题。
	msg := humanizeACMEErr(fmt.Errorf("[666086.xyz] acme: error presenting token: %w",
		newDNSPodError("写入 TXT 记录 _acme-challenge.666086.xyz", apiErr.Code, apiErr.Message)))
	if !strings.Contains(msg, "Token") || !strings.Contains(msg, "10004") {
		t.Fatalf("提示应包含 Token 与错误码，实际：%q", msg)
	}
}

// CleanUp 只能删掉与本次挑战值相同的记录：同名多值（根域 + 泛域）和用户自建 TXT 都不能误删。
func TestDNSPodCleanUpOnlyMatchingValue(t *testing.T) {
	const challenge = "BJ4ujlS-YYvIhDguIegbNyUNIQ-UbKioV00v9nxCTuI"

	deleted := make([]string, 0, 2)
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/Domain.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":987654,"name":"666086.xyz","status":"enable"}]}`)
		case "/Record.List":
			if r.Form.Get("sub_domain") != "_acme-challenge" {
				t.Errorf("sub_domain 应为 _acme-challenge，实际 %q", r.Form.Get("sub_domain"))
			}
			_, _ = fmt.Fprintf(w, `{"status":{"code":"1","message":""},"records":[
				{"id":"111","name":"_acme-challenge","type":"TXT","value":"%s"},
				{"id":"222","name":"_acme-challenge","type":"TXT","value":"someone-elses"}
			]}`, challenge)
		case "/Record.Remove":
			deleted = append(deleted, r.Form.Get("record_id"))
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""}}`)
		default:
			t.Errorf("意外请求：%s", r.URL.Path)
		}
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	if err := p.cleanupAt("_acme-challenge.666086.xyz", challenge); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "111" {
		t.Fatalf("只应删除值为本次挑战的那条记录，实际删除 %v", deleted)
	}
}

// 复现本次线上故障：_acme-challenge 被 CNAME 带到主域名后，
// 挑战 FQDN 等于 zone，必须用 @ 这个主机记录写入，而不是报「找不到子域名」。
func TestDNSPodApexRecordUsesAtMarker(t *testing.T) {
	var gotSub, gotType, gotLine string
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/Domain.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":987654,"name":"666086.xyz","status":"enable"}]}`)
		case "/Record.List":
			// 根域下已有用户的 SPF 等 TXT，不能被当成同值记录复用
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"records":[{"id":"9","name":"@","type":"TXT","value":"v=spf1 -all"}]}`)
		case "/Record.Create":
			gotSub, gotType, gotLine = r.Form.Get("sub_domain"), r.Form.Get("record_type"), r.Form.Get("record_line")
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"record":{"id":"333"}}`)
		default:
			t.Errorf("意外请求：%s", r.URL.Path)
		}
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	if err := p.presentAt("666086.xyz", "challenge-value"); err != nil {
		t.Fatal(err)
	}
	if gotSub != "@" {
		t.Fatalf("根域记录的主机记录必须是 @，实际 %q", gotSub)
	}
	if gotType != "TXT" || gotLine != "默认" {
		t.Fatalf("记录类型/线路不对：%q %q", gotType, gotLine)
	}
}

// Present 若发现同名同值记录已存在，应复用而不是重复创建。
func TestDNSPodPresentSkipsDuplicate(t *testing.T) {
	const challenge = "duplicate-challenge-value"

	created := 0
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/Domain.List":
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":987654,"name":"666086.xyz","status":"enable"}]}`)
		case "/Record.List":
			_, _ = fmt.Fprintf(w, `{"status":{"code":"1","message":""},"records":[{"id":"111","name":"_acme-challenge","type":"TXT","value":"%s"}]}`, challenge)
		case "/Record.Create":
			created++
			_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"record":{"id":"333"}}`)
		}
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	if err := p.presentAt("_acme-challenge.666086.xyz", challenge); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("同名同值记录已存在时不应重复创建，实际创建 %d 次", created)
	}
}

func TestDNSPodPreflightRejectsForeignDomain(t *testing.T) {
	api, done := newTestDNSPodServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":{"code":"1","message":""},"domains":[{"id":1,"name":"example.com","status":"enable"}]}`)
	})
	defer done()

	p := newDNSPodProvider("12345,abcdef", 600, nil)
	p.api = api
	if _, err := p.Preflight([]string{"666086.xyz", "*.666086.xyz"}); err == nil {
		t.Fatal("域名不在账号下时应预检失败")
	} else if !strings.Contains(err.Error(), "不在这个 DNSPod 账号下") {
		t.Fatalf("错误文案应说清原因，实际：%v", err)
	}
	if zones, err := p.Preflight([]string{"example.com", "*.example.com"}); err != nil {
		t.Fatalf("域名在账号下应通过：%v", err)
	} else if !strings.Contains(zones, "example.com") {
		t.Fatalf("应回带匹配到的 zone：%q", zones)
	}
}
