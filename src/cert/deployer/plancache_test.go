package deployer

import (
	"strings"
	"testing"
	"time"
)

// 预检计划必须能按 plan_id 取回：部署以用户确认的那份计划为准，
// 不再依赖「重新计算一遍再比哈希」。
func TestPlanCachePutGet(t *testing.T) {
	c := &planCache{ttl: time.Minute, items: map[string]*cachedPlan{}}
	j := &journal{PlanID: "abc123"}
	c.put(j)
	got, ok := c.get("abc123")
	if !ok || got != j {
		t.Fatal("应按 plan_id 取回同一份计划")
	}
	if _, ok := c.get(""); ok {
		t.Fatal("空 plan_id 不应命中")
	}
	if _, ok := c.get("missing"); ok {
		t.Fatal("未知 plan_id 不应命中")
	}
}

// 计划过期后不可再用，避免拿很久以前的确认结果去改系统。
func TestPlanCacheExpiry(t *testing.T) {
	c := &planCache{ttl: time.Nanosecond, items: map[string]*cachedPlan{}}
	c.put(&journal{PlanID: "old"})
	time.Sleep(2 * time.Millisecond)
	if _, ok := c.get("old"); ok {
		t.Fatal("过期计划不应命中")
	}
}

// 只保留最近 8 份，防止内存无限增长。
func TestPlanCacheEvicts(t *testing.T) {
	c := &planCache{ttl: time.Minute, items: map[string]*cachedPlan{}}
	for _, id := range []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"} {
		c.put(&journal{PlanID: id})
	}
	if _, ok := c.get("p1"); ok {
		t.Fatal("最旧的计划应被淘汰")
	}
	if _, ok := c.get("p9"); !ok {
		t.Fatal("最新的计划应保留")
	}
	if len(c.items) != 8 {
		t.Fatalf("缓存条数应为 8，实际 %d", len(c.items))
	}
}

// 「正在运行」的提示必须说明阶段与耗时，否则用户只会看到一句无信息量的忙碌。
func TestBusyErrorExplainsStage(t *testing.T) {
	start := time.Now().Add(-42 * time.Second)
	err := busyError(StageRestart, start)
	if d := detailOf(err); !strings.Contains(d, "重启飞牛服务") || !strings.Contains(d, "42") {
		t.Fatalf("忙碌提示缺少阶段或耗时：%q", d)
	}
	if codeOf(err) != CodeBusy {
		t.Fatalf("错误码应为 BUSY，实际 %s", codeOf(err))
	}
	// 长时间卡住时给出可操作的下一步。
	long := busyError(StageRestart, time.Now().Add(-10*time.Minute))
	if d := detailOf(long); !strings.Contains(d, "停用再启用") {
		t.Fatalf("卡住超过 5 分钟应给出重启建议：%q", d)
	}
}
