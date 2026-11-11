package core

import "fmt"

// Migrate 按版本链升级状态。新增结构版本时在此追加 case。
// 返回 (原版本, 是否发生迁移, 错误)。
func Migrate(st *State) (int, bool, error) {
	from := st.SchemaVersion
	if from < 0 {
		from = 0
	}
	if from > CurrentSchema {
		return from, false, fmt.Errorf("配置版本 v%d 高于当前应用支持的 v%d，请升级应用", from, CurrentSchema)
	}
	for v := from; v < CurrentSchema; v++ {
		switch v {
		case 0:
			// v0 -> v1：补齐默认值与空切片；v0 没有独立结构，Normalize 即可。
		default:
			return from, false, fmt.Errorf("缺少 v%d -> v%d 的迁移逻辑", v, v+1)
		}
	}
	st.SchemaVersion = CurrentSchema
	st.Normalize()
	return from, from != CurrentSchema, nil
}
