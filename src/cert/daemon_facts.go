package cert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 本文件负责回答一个问题：守护连不上时，到底缺哪一环。
//
// 「部署服务未连接」这句话本身没有信息量：可能是 root 侧守护没起来、
// 起来后崩了、Socket 残留成了普通文件、权限组不对、或者上次同步把
// 自己写进了无法回滚的状态。这里逐项给出事实，用户复制诊断即可定位。
//
// 只读，不改任何状态；只报告主应用有权查看的内容（守护日志里的
// cert-deployer 相关行不含私钥）。

// daemonFacts 返回守护不可用时的可读事实清单。
func (m *Manager) daemonFacts(cause error) []string {
	facts := []string{}
	sock := m.pushClient.socket

	// 1. Socket 本身的状态。
	if st, err := os.Lstat(sock); err != nil {
		if os.IsNotExist(err) {
			facts = append(facts, fmt.Sprintf("守护 Socket %s 不存在：root 侧守护进程没有启动（或启动后立即退出）", sock))
		} else if os.IsPermission(err) {
			facts = append(facts, fmt.Sprintf("主应用无权查看守护 Socket %s（%v）", sock, err))
		} else {
			facts = append(facts, fmt.Sprintf("无法读取守护 Socket %s：%v", sock, err))
		}
	} else if st.Mode()&os.ModeSocket == 0 {
		facts = append(facts, fmt.Sprintf("守护 Socket %s 存在但不是套接字（权限 %s，%d 字节）：多半是上次异常退出留下的残留文件，重启应用会清理",
			sock, st.Mode().Perm(), st.Size()))
	} else {
		facts = append(facts, fmt.Sprintf("守护 Socket %s 已存在（权限 %s）：守护曾成功启动过；若连接被拒，通常是应用组与 Socket 属组不一致",
			sock, st.Mode().Perm()))
	}

	// 2. 连接失败原文（区分「文件不存在」「权限拒绝」「超时」）。
	if cause != nil {
		facts = append(facts, "连接结果："+cause.Error())
	}

	// 3. 守护进程是否还活着。PID 由启动脚本写入数据目录。
	if pid := m.readDaemonPID(); pid != "" {
		if _, err := os.Stat(filepath.Join("/proc", pid)); err == nil {
			facts = append(facts, "守护进程：pid "+pid+" 仍在运行，但未响应请求（可能卡在重启飞牛服务）")
		} else {
			facts = append(facts, "守护进程：pid "+pid+" 已不存在，说明启动后退出（原因见下面的日志）")
		}
	} else {
		facts = append(facts, "守护进程：没有 PID 文件，说明启动脚本没有拉起守护（应用是否以 root 启动？）")
	}

	// 4. 守护日志尾部：真正的原因通常只在这里。
	if tail := m.daemonLogTail(); len(tail) > 0 {
		facts = append(facts, "守护日志尾部：")
		facts = append(facts, tail...)
	}

	facts = append(facts, "处理办法：到飞牛应用中心停用再启用 fnGate（会重启 root 侧守护并清理残留 Socket）；"+
		"若仍显示未连接，把这整段诊断发出来即可定位")
	return facts
}

// readDaemonPID 读取启动脚本写入的守护 PID。
func (m *Manager) readDaemonPID() string {
	raw, err := os.ReadFile(filepath.Join(m.opt.DataDir, "cert-deployer.pid"))
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(raw))
	pid = strings.Trim(pid, "\r\n\t ")
	for _, r := range pid {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return pid
}

// daemonLogTail 取主应用日志里最近几条 cert-deployer 相关行。
// 守护的 stdout/stderr 被启动脚本重定向到同一份 fngate.log。
func (m *Manager) daemonLogTail() []string {
	path := filepath.Join(m.opt.DataDir, "fngate.log")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	const window = 32 << 10
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	offset := int64(0)
	if st.Size() > window {
		offset = st.Size() - window
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return nil
	}
	raw := make([]byte, window)
	n, _ := f.Read(raw)
	lines := strings.Split(string(raw[:n]), "\n")

	out := []string{}
	for _, line := range lines {
		if !strings.Contains(line, "cert-deployer") && !strings.Contains(line, "部署守护") {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 单行截断，避免整屏都是日志。
		if r := []rune(line); len(r) > 220 {
			line = string(r[:220]) + "…"
		}
		out = append(out, "  "+line)
	}
	if len(out) > 6 {
		out = out[len(out)-6:]
	}
	return out
}
