package acme

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
)

func specOf(t *testing.T, typ string) ProviderSpec {
	t.Helper()
	spec, err := validateProviderType(typ)
	if err != nil {
		t.Fatalf("取服务商定义失败：%v", err)
	}
	return spec
}

func TestCheckProviderFields(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		fields  map[string]string
		wantErr string // 空表示应当通过
	}{
		{
			name: "阿里云缺 Secret", typ: "alidns",
			fields:  map[string]string{"access_key": "LTAIxxx"},
			wantErr: "AccessKey Secret",
		},
		{
			name: "阿里云填齐", typ: "alidns",
			fields: map[string]string{"access_key": "LTAIxxx", "secret_key": "yyy"},
		},
		{
			name: "Cloudflare 什么都没填", typ: "cloudflare",
			fields:  map[string]string{},
			wantErr: "DNS API Token",
		},
		{
			name: "Cloudflare 只有 Token", typ: "cloudflare",
			fields: map[string]string{"api_token": "tok"},
		},
		{
			name: "Cloudflare 只有邮箱没有 Key", typ: "cloudflare",
			fields:  map[string]string{"email": "a@b.com"},
			wantErr: "DNS API Token",
		},
		{
			name: "Cloudflare 邮箱加 Global Key", typ: "cloudflare",
			fields: map[string]string{"email": "a@b.com", "api_key": "k"},
		},
		{
			name: "DNSPod Token 缺少逗号", typ: "dnspod",
			fields:  map[string]string{"api_key": "abcdef123456"},
			wantErr: "ID,Token",
		},
		{
			name: "DNSPod Token 格式正确", typ: "dnspod",
			fields: map[string]string{"api_key": "12345,abcdef"},
		},
		{
			name: "手动模式无需凭据", typ: "manual",
			fields: map[string]string{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkProviderFields(specOf(t, c.typ), normalizeFields(c.fields))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("预期通过，实际报错：%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("预期报错包含 %q，实际通过", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("错误信息不含 %q：%v", c.wantErr, err)
			}
		})
	}
}

func TestNormalizeFields(t *testing.T) {
	got := normalizeFields(map[string]string{"  Access_Key ": " LTAI123 ", "SECRET_KEY": " s3cret "})
	if got["access_key"] != "LTAI123" {
		t.Fatalf("键名未归一化或值未去空白：%v", got)
	}
	if got["secret_key"] != "s3cret" {
		t.Fatalf("大写键名未归一化：%v", got)
	}
}

func TestVerifyDNSManualAndUnknown(t *testing.T) {
	if res := VerifyDNS("manual", credentials{}); !res.OK {
		t.Fatalf("手动模式应始终可用，实际：%+v", res)
	}
	if res := VerifyDNS("no-such-provider", credentials{}); res.OK {
		t.Fatal("未知服务商不应判定为可用")
	}
}

// 本地缺字段时必须在发起任何网络请求前就给出结论。
func TestVerifyDNSRejectsIncompleteWithoutNetwork(t *testing.T) {
	res := VerifyDNS("alidns", credentials{"access_key": "LTAIxxx"})
	if res.OK {
		t.Fatal("缺少 Secret 不应判定为可用")
	}
	if !strings.Contains(res.Message, "Secret") {
		t.Fatalf("错误提示不明确：%s", res.Message)
	}
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func TestNetworkHint(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"DNS 解析失败", &net.DNSError{Err: "no such host", Name: "dns.aliyuncs.com", IsNotFound: true}, "DNS 解析失败"},
		{"连接被拒绝", errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), "连接被拒绝"},
		{"超时", fakeTimeout{}, "连接超时"},
		{"网络不可达", errors.New("dial tcp: network is unreachable"), "网络不可达"},
		{"证书问题", errors.New("x509: certificate signed by unknown authority"), "TLS 证书校验失败"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := networkHint(c.err)
			if !strings.Contains(got, c.want) {
				t.Fatalf("预期含 %q，实际：%q", c.want, got)
			}
		})
	}
	// 业务错误不应被网络错误翻译吞掉
	if got := networkHint(errors.New("InvalidAccessKeyId.NotFound")); got != "" {
		t.Fatalf("业务错误不应匹配网络提示，实际：%q", got)
	}
}

func TestHumanizeAliErr(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{"InvalidAccessKeyId.NotFound", "不存在"},
		{"SignatureDoesNotMatch", "Secret"},
		{"Forbidden.RAM", "云解析权限"},
		{"InvalidSecurityToken.Expired", "STS Token"},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			got := humanizeAliErr(&tea.SDKError{Code: tea.String(c.code)})
			if !strings.Contains(got, c.want) {
				t.Fatalf("预期含 %q，实际：%q", c.want, got)
			}
		})
	}
}

func TestHumanizeCloudflareErr(t *testing.T) {
	if got := humanizeCFErr(errors.New("HTTP status 401: Unauthorized")); !strings.Contains(got, "无效或已过期") {
		t.Fatalf("401 提示不对：%q", got)
	}
	if got := humanizeCFErr(errors.New("HTTP status 403: Forbidden")); !strings.Contains(got, "权限不足") {
		t.Fatalf("403 提示不对：%q", got)
	}
}

func TestHumanizeDNSPodErr(t *testing.T) {
	// DNSPod 的错误统一走 dnsProviderError 翻译：必须保留原始错误码与建议。
	got := newDNSPodError("验证凭据", "10004", "Token 验证失败").Human()
	if !strings.Contains(got, "Token") || !strings.Contains(got, "10004") {
		t.Fatalf("Token 校验失败提示不对：%q", got)
	}
	// 格式问题在本地就该拦下，不浪费一次外网请求。
	if res := verifyDNSPod(credentials{"api_key": "abcdef"}); res.OK || !strings.Contains(res.Message, "ID,Token") {
		t.Fatalf("缺少逗号应在本地拦下：%+v", res)
	}
	if res := verifyDNSPod(credentials{}); res.OK {
		t.Fatal("空凭据应报错")
	}
}
