package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	alidns "github.com/alibabacloud-go/alidns-20150109/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudflare/cloudflare-go"
)

// VerifyResult 是「测试连接」的结果。
type VerifyResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// VerifyDNS 用只读接口探测凭据：能不能连上、鉴权过不过、有没有解析管理权限。
// 只会调「列域名 / 列 Zone」这类只读方法，不会创建、修改或删除任何 DNS 记录，
// 因此可以安全地在「添加服务商」时先跑一遍，而不是等到申请证书才暴露填错的凭据。
func VerifyDNS(pType string, cred credentials) VerifyResult {
	switch pType {
	case "manual":
		return VerifyResult{OK: true, Message: "手动 TXT 模式无需凭据，申请时按提示添加记录即可"}
	case "alidns":
		return verifyAliDNS(cred)
	case "dnspod":
		return verifyDNSPod(cred)
	case "cloudflare":
		return verifyCloudflare(cred)
	}
	return VerifyResult{Message: "不支持的 DNS 服务商：" + pType}
}

// ---------- 阿里云 DNS ----------

func verifyAliDNS(cred credentials) VerifyResult {
	ak, sk := cred.get("access_key"), cred.get("secret_key")
	if ak == "" || sk == "" {
		return VerifyResult{Message: "请填写 AccessKey ID 与 AccessKey Secret"}
	}
	// 与 lego provider 保持一致：RegionID 只影响接入点，不影响鉴权结果。
	region := cred.get("region_id")
	if region == "" {
		region = "cn-hangzhou"
	}
	cfg := new(openapi.Config).
		SetRegionId(region).
		SetAccessKeyId(ak).
		SetAccessKeySecret(sk).
		SetConnectTimeout(8000).
		SetReadTimeout(12000)
	if sts := cred.get("security_token"); sts != "" {
		cfg.SetSecurityToken(sts)
	}

	client, err := alidns.NewClient(cfg)
	if err != nil {
		return VerifyResult{Message: "初始化阿里云客户端失败", Detail: err.Error()}
	}
	// DescribeDomains 是只读接口，PageSize=1 只为确认鉴权通过，不拉取大量数据。
	resp, err := client.DescribeDomains(&alidns.DescribeDomainsRequest{
		PageNumber: tea.Int64(1),
		PageSize:   tea.Int64(1),
	})
	if err != nil {
		return VerifyResult{Message: humanizeAliErr(err)}
	}
	var total int64
	if resp != nil && resp.Body != nil && resp.Body.TotalCount != nil {
		total = *resp.Body.TotalCount
	}
	msg := fmt.Sprintf("凭据有效，账号下可管理 %d 个域名", total)
	if total == 0 {
		msg = "凭据有效，但该账号下没有域名（可在阿里云先添加解析域名）"
	}
	return VerifyResult{OK: true, Message: msg}
}

func humanizeAliErr(err error) string {
	if hint := networkHint(err); hint != "" {
		return hint
	}
	var sdkErr *tea.SDKError
	if errors.As(err, &sdkErr) {
		code := strings.TrimSpace(tea.StringValue(sdkErr.Code))
		msg := strings.TrimSpace(tea.StringValue(sdkErr.Message))
		switch code {
		case "InvalidAccessKeyId.NotFound", "InvalidAccessKeyId":
			return "AccessKey ID 不存在，请核对是否复制完整"
		case "SignatureDoesNotMatch":
			return "AccessKey Secret 与 AccessKey ID 不匹配，请重新复制 Secret"
		case "Forbidden.RAM", "Forbidden", "NoPermission":
			return "该 AccessKey 没有云解析权限，请授予 AliyunDNSFullAccess 策略"
		case "InvalidSecurityToken.Malformed", "InvalidSecurityToken.Expired":
			return "STS Token 无效或已过期，请重新获取临时凭据"
		case "InvalidTimeStamp.Expired":
			return "请求时间戳异常，请检查 NAS 的系统时间是否准确"
		}
		if msg != "" {
			return "阿里云返回错误：" + msg
		}
		if code != "" {
			return "阿里云返回错误码：" + code
		}
	}
	return "调用阿里云接口失败：" + err.Error()
}

// ---------- 腾讯云 DNSPod ----------

func verifyDNSPod(cred credentials) VerifyResult {
	token := cred.get("api_key")
	if token == "" {
		return VerifyResult{Message: "请填写 DNSPod API Token"}
	}
	if !strings.Contains(token, ",") {
		return VerifyResult{Message: "API Token 格式应为「ID,Token」，两段用英文逗号分隔"}
	}
	// 与签发时用的是同一套客户端：测试连接能过，申请时就不会因为凭据/分页问题卡住。
	api := newDNSPodAPI(token)
	zones, err := api.listZones()
	if err != nil {
		var apiErr *dnspodAPIError
		if errors.As(err, &apiErr) {
			return VerifyResult{
				Message: newDNSPodError("验证凭据", apiErr.Code, apiErr.Message).Human(),
				Detail:  err.Error(),
			}
		}
		if hint := networkHint(err); hint != "" {
			return VerifyResult{Message: hint, Detail: err.Error()}
		}
		return VerifyResult{Message: "调用 DNSPod 接口失败：" + err.Error()}
	}
	if len(zones) == 0 {
		return VerifyResult{OK: true, Message: "凭据有效，但该账号下没有域名（可先在 DNSPod 添加解析域名）"}
	}
	return VerifyResult{OK: true, Message: fmt.Sprintf("凭据有效，账号下可管理 %d 个域名", len(zones))}
}

// ---------- Cloudflare ----------

func verifyCloudflare(cred credentials) VerifyResult {
	token := cred.get("api_token")
	email, key := cred.get("email"), cred.get("api_key")

	var api *cloudflare.API
	var err error
	switch {
	case token != "":
		api, err = cloudflare.NewWithAPIToken(token)
	case email != "" && key != "":
		api, err = cloudflare.New(key, email)
	default:
		return VerifyResult{Message: "请填写 DNS API Token，或同时填写邮箱与 Global API Key"}
	}
	if err != nil {
		return VerifyResult{Message: "初始化 Cloudflare 客户端失败", Detail: err.Error()}
	}

	// ListZones 需要 Zone:Read；DNS 编辑凭据正常也应具备该只读权限。
	res, err := cfListZones(api)
	if err != nil {
		return VerifyResult{Message: humanizeCFErr(err)}
	}
	msg := fmt.Sprintf("凭据有效，可访问 %d 个 Zone", len(res))

	// 若另配了独立的 Zone 只读凭据，顺带验证它是否可用（不通过不影响主凭据判定）。
	if zt := cred.get("zone_token"); zt != "" && zt != token {
		if zapi, zerr := cloudflare.NewWithAPIToken(zt); zerr == nil {
			if zres, zerr := cfListZones(zapi); zerr != nil {
				return VerifyResult{Message: "DNS Token 可用，但 Zone Token 校验失败：" + humanizeCFErr(zerr)}
			} else {
				msg += fmt.Sprintf("，Zone Token 亦可访问 %d 个 Zone", len(zres))
			}
		}
	}
	return VerifyResult{OK: true, Message: msg}
}

func cfListZones(api *cloudflare.API) ([]cloudflare.Zone, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := api.ListZonesContext(ctx)
	if err != nil {
		return nil, err
	}
	return res.Result, nil
}

func humanizeCFErr(err error) string {
	if hint := networkHint(err); hint != "" {
		return hint
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "401"), strings.Contains(msg, "Unauthorized"):
		return "Token 无效或已过期（401），请在 Cloudflare 重新生成"
	case strings.Contains(msg, "403"), strings.Contains(msg, "Forbidden"):
		return "Token 权限不足（403），需要 Zone:Read 与 DNS:Edit"
	case strings.Contains(msg, "429"):
		return "Cloudflare 接口调用频率超限，请稍后再试"
	}
	return "调用 Cloudflare 接口失败：" + msg
}

// ---------- 通用网络错误翻译 ----------

// networkHint 把 Go 的底层网络错误翻译成用户能看懂的话；
// 返回空串表示不是网络层问题，交给各家的业务错误处理。
func networkHint(err error) string {
	if err == nil {
		return ""
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "连接超时，请检查 NAS 是否能正常访问外网"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such host"):
		return "DNS 解析失败，请检查 NAS 的网络与 DNS 设置"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒绝，请检查出口防火墙或代理设置"
	case strings.Contains(msg, "context deadline exceeded"):
		return "连接超时，请检查 NAS 是否能正常访问外网"
	case strings.Contains(msg, "x509"), strings.Contains(msg, "certificate"):
		return "TLS 证书校验失败，请检查 NAS 的系统时间或代理设置"
	case strings.Contains(msg, "network is unreachable"):
		return "网络不可达，请检查 NAS 的网络连接"
	}
	return ""
}
