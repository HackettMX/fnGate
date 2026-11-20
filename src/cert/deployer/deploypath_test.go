package deployer

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 路径属性（属主、权限位、硬链接数）依赖 Linux 的 stat，Windows 上不可靠。
func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("仅在 Linux 上校验文件权限语义")
	}
}

// 这些用例锁定「路径安全检查」的边界：真机上出现过合法证书被误判为不安全的情况，
// 因此把「哪些算可写、哪些只提示」写成回归测试。

func writePerm(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func hasSubstr(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func TestPathFactsStructural(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	e := &Engine{CertRoot: root, Secure: false}

	good := filepath.Join(root, "example.com", "1795143925", "cert.pem")
	writePerm(t, good, 0o644)
	if _, blocking, _ := e.pathFacts(good, true); len(blocking) != 0 {
		t.Fatalf("正常证书路径不应被拒绝：%v", blocking)
	}

	outside := filepath.Join(t.TempDir(), "cert.pem")
	writePerm(t, outside, 0o644)
	if _, blocking, _ := e.pathFacts(outside, true); !hasSubstr(blocking, "不在证书根目录") {
		t.Fatalf("根目录外的路径应被拒绝：%v", blocking)
	}

	worldWritable := filepath.Join(root, "w", "cert.pem")
	writePerm(t, worldWritable, 0o666)
	if _, blocking, _ := e.pathFacts(worldWritable, true); !hasSubstr(blocking, "其他用户可写") {
		t.Fatalf("其他人可写的文件应被拒绝：%v", blocking)
	}

	link := filepath.Join(root, "l", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, link); err != nil {
		t.Skipf("当前平台不支持软链接：%v", err)
	}
	if _, blocking, _ := e.pathFacts(link, true); !hasSubstr(blocking, "软链接") {
		t.Fatalf("软链接应被拒绝：%v", blocking)
	}

	missing := filepath.Join(root, "nope", "cert.pem")
	if _, blocking, _ := e.pathFacts(missing, true); !hasSubstr(blocking, "路径不存在") {
		t.Fatalf("缺失路径应提示不存在：%v", blocking)
	}
}

// 组可写的目录（fnOS 常见 0775 root:trim）不应阻断，只有其他用户可写或非 root 所有才阻断。
func TestDirFactsTolerance(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	sub := filepath.Join(root, "example.com", "1795143925")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "cert.pem")
	writePerm(t, file, 0o644)

	// 组可写的「所在目录」：仅在属主为当前用户（测试环境非 root）时不阻断，
	// 因此这里只断言不会被判定为「其他用户可写」。
	if err := os.Chmod(sub, 0o775); err != nil {
		t.Fatal(err)
	}
	e := &Engine{CertRoot: root, Secure: true}
	_, blocking, _ := e.pathFacts(file, true)
	if hasSubstr(blocking, "其他用户可写") {
		t.Fatalf("0775 的目录不应因组写位被拒绝：%v", blocking)
	}

	// 所在目录「其他用户可写」是唯一阻断项：任何本地用户都能替换文件。
	if err := os.Chmod(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, blocking, _ := e.pathFacts(file, true); !hasSubstr(blocking, "其他用户可写") {
		t.Fatalf("0777 的所在目录应被拒绝：%v", blocking)
	}
}
