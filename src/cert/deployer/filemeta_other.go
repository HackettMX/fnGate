//go:build !linux

package deployer

import "os"

// 非 Linux 平台仅供本地编译/测试，deployer 生产上只在 fnOS(Linux) 运行。
// 返回安全默认值让校验 fail-closed（UID -1 不等于 0，会被拒绝）。

func fileNlink(info os.FileInfo) uint64 { return 0 }

func fileUID(info os.FileInfo) int { return -1 }

func fileGID(info os.FileInfo) int { return -1 }
