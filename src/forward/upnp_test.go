package forward

import (
	"strings"
	"testing"

	"github.com/huin/goupnp/soap"
)

func TestPortMappingVariants(t *testing.T) {
	// 永久租期：4 组降级，先标准后兼容，有限租期用 86400。
	got := portMappingVariants(0)
	want := []struct {
		remoteHost string
		lease      uint32
	}{{"", 0}, {"*", 0}, {"", 86400}, {"*", 86400}}
	if len(got) != len(want) {
		t.Fatalf("永久租期应有 %d 组变体，实际 %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("变体 %d 应为 %+v，实际 %+v", i, want[i], got[i])
		}
	}

	// 有限租期：不改语义，只试两种 RemoteHost。
	got = portMappingVariants(3600)
	if len(got) != 2 {
		t.Fatalf("有限租期应有 2 组变体，实际 %d", len(got))
	}
	for _, v := range got {
		if v.lease != 3600 {
			t.Fatalf("有限租期不应被改写，实际 %d", v.lease)
		}
	}
}

func TestFriendlyErrorKeepsRouterDescription(t *testing.T) {
	// 模拟路由器 402 + 原始描述。真实 SOAP fault 的 Detail.Raw 里带描述，
	// 之前的实现把它吞掉，只剩"参数错误"，无法诊断。
	fault := &soap.SOAPFaultError{
		FaultString: "UPnPError",
	}
	fault.Detail.Raw = []byte(`<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>402</errorCode><errorDescription>LeaseDuration must be greater than zero</errorDescription></UPnPError>`)

	msg := friendlyError(fault)
	if !strings.Contains(msg, "LeaseDuration must be greater than zero") {
		t.Fatalf("应保留路由器原始错误描述，实际：%s", msg)
	}
	if !strings.Contains(msg, "Invalid Args") {
		t.Fatalf("应保留错误码文案，实际：%s", msg)
	}
}

func TestExtractXMLTag(t *testing.T) {
	raw := `<UPnPError><errorCode>402</errorCode><errorDescription>  Bad RemoteHost  </errorDescription></UPnPError>`
	if got := extractXMLTag(raw, "errorDescription"); got != "Bad RemoteHost" {
		t.Fatalf("期望去掉首尾空白的描述，实际 %q", got)
	}
	if got := extractXMLTag(raw, "other"); got != "" {
		t.Fatalf("非目标标签应返回空串，实际 %q", got)
	}
}

func soapFault(code int) error {
	f := &soap.SOAPFaultError{FaultString: "UPnPError"}
	f.Detail.UPnPError.Errorcode = code
	return f
}

func TestTryPortMappingVariantsFallsBackOn402(t *testing.T) {
	variants := portMappingVariants(0)
	attempts := 0
	// 模拟固件：前两次（空/* + 原租期 0）拒 402，第三次的 86400 租期成功。
	err := tryPortMappingVariants(variants, func(v portMappingVariant) error {
		attempts++
		if v.lease == 0 {
			return soapFault(402)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("第 3 组降级应成功，实际：%v", err)
	}
	if attempts != 3 {
		t.Fatalf("应尝试 3 次后成功，实际 %d 次", attempts)
	}
}

func TestTryPortMappingVariantsStopsOnOtherError(t *testing.T) {
	attempts := 0
	err := tryPortMappingVariants(portMappingVariants(0), func(v portMappingVariant) error {
		attempts++
		return soapFault(718) // 端口冲突，明确错误，不该继续降级
	})
	if upnpErrorCode(err) != 718 {
		t.Fatalf("应原样返回 718，实际：%v", err)
	}
	if attempts != 1 {
		t.Fatalf("非 402 错误应立即停止，实际尝试 %d 次", attempts)
	}
}

func TestTryPortMappingVariantsAllFail(t *testing.T) {
	attempts := 0
	err := tryPortMappingVariants(portMappingVariants(0), func(v portMappingVariant) error {
		attempts++
		return soapFault(402)
	})
	if upnpErrorCode(err) != 402 {
		t.Fatalf("全部失败应返回最后一次的 402，实际：%v", err)
	}
	if attempts != 4 {
		t.Fatalf("应尝试全部 4 组，实际 %d 次", attempts)
	}
}
