<p align="center">
  <img src="assets/icon-master.png" width="112" alt="fnGate">
</p>

<h1 align="center">fnGate · 路由网关</h1>

<p align="center">
  飞牛 fnOS 原生网关应用：<b>路由转发</b> · <b>反向代理</b> · <b>证书管理</b> 三模块合一
</p>

<p align="center">
  <a href="https://github.com/HackettMX/fnGate/releases"><img src="https://img.shields.io/github/v/release/HackettMX/fnGate?label=release&color=2f81f7" alt="release"></a>
  <a href="https://github.com/HackettMX/fnGate/actions/workflows/build.yml"><img src="https://github.com/HackettMX/fnGate/actions/workflows/build.yml/badge.svg" alt="build"></a>
  <img src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white" alt="go">
  <img src="https://img.shields.io/badge/fnOS-0.9.0%2B-00A9A5" alt="fnos">
  <img src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64%20%7C%20arm-lightgrey" alt="arch">
</p>

<p align="center">
  <a href="#-亮点">亮点</a> ·
  <a href="#-功能">功能</a> ·
  <a href="#-dns-01-踩坑记录">DNS-01 踩坑</a> ·
  <a href="#-安全">安全</a> ·
  <a href="#-安装">安装</a> ·
  <a href="#-开发">开发</a>
</p>

---

## ✨ 亮点

| | |
|---|---|
| **原生应用** | 标准 `.fpk` 包，Go 静态二进制，安装不联网、不拉任何 Docker 镜像 |
| **不占管理端口** | 管理面只走飞牛统一网关 Unix Socket（`/app/fngate`），不监听管理 TCP |
| **三架构** | `linux/amd64`、`linux/arm64`、`linux/arm`（ARMv6+ 同一份二进制） |
| **安全默认** | 同源校验 + 写操作 CSRF Token；私钥与 DNS 凭据隔离在 `secrets/`（`0700`/`0600`） |
| **零重启生效** | 证书续期后无需重启进程，已建立连接不中断 |

---

## 🧩 功能

### 1. 路由转发

基于 UPnP IGD 的端口映射管理，解决「家里 NAS 想被外网访问，但要手动进路由器」的问题。

- UPnP **IGD1 / IGD2** 自动发现局域网网关
- 映射增 / 删 / 重新启用
- 路由器重启或映射丢失后**自动补发**（可手动暂停）
- 网关指纹保护，避免误删其他设备的映射
- 枚举外部已有映射，可选择性清理

### 2. 反向代理

双层模型，配置一次即可长期稳定运行：

```
入口 Listener  =  端口 / 协议 / 绑定地址 / TLS
路由 Route     =  域名 / 路径  →  后端
```

| 能力 | 说明 |
|---|---|
| 协议 | HTTP、HTTPS、TCP（TCP 支持 TLS SNI 分流） |
| 路由匹配 | 精确域名、泛域名 `*.example.com`、空域名任意匹配、路径前缀 / 精确匹配、**最长路径优先** |
| 后端 | 保留 `http/https` scheme、路径前缀剥离、`X-Forwarded-*` / `X-Real-IP`、请求头改写、后端 TLS 校验开关、WebSocket、超时 |
| 内置 | HTTP→HTTPS 跳转、HSTS、访问日志、健康检查 |
| 增量应用 | 纯路由变更不重建监听，已建立连接不中断 |
| 证书 | 按 `cert_id` 引用，续期后零重启自动生效 |

> **明确不做**（按设计决策）：访问控制、限流 / WAF、缓存、多后端负载均衡。这些交给上游，本应用只做好网关本身。

### 3. 证书管理

#### 3.1 证书库

- 按**来源**分 tab：ACME 申请 / 手动上传 / 自签证书 / 飞牛系统证书
- 状态（有效 / 即将到期 / 已过期 / 文件缺失）作为**筛选**，叠加关键词搜索
- 手动上传 PEM（私钥 + 证书链，自动解析 SAN / 有效期 / 通配符）
- 飞牛系统证书**只读导入**（root helper 复制为应用私有快照，绝不回写系统证书库）
- 一键自签内网证书（ECDSA / RSA）
- 引用保护：被反向代理引用的证书不可删除

#### 3.2 证书申请（ACME）

- CA：**Let's Encrypt**（生产 / Staging）、自定义 Directory（含 EAB 外部账户绑定）
- DNS-01 验证服务商：

| 服务商 | 凭据 | 备注 |
|---|---|---|
| 腾讯云 DNSPod | `ID,Token` | 自研实现，**支持根域 `@` 记录与 `*` 通配 CNAME 跟随** |
| 阿里云 DNS | AccessKey ID / Secret（可选 STS） | 支持自定义 Region |
| Cloudflare | API Token（或邮箱 + Global API Key） | 推荐 Token：`Zone:Read` + `DNS:Edit` |
| 手动 | 无 | 展示 TXT 记录，添加后点「我已添加」或等待自动探测 |

- 支持**泛域名证书**、**自动续期**（到期前 30 天检查、失败退避、原子切换）
- 凭据校验：服务商可「测试连接」（只读探测），任务失败时日志保留**服务商原始错误码与原文**
- 只读**预检**：下单前先核对域名是否真的托管在该账号，不通过就直接提示

#### 3.3 域名解析

凭据集中管理，不用每次请求都打外网：

- 列表显示脱敏账号、最近校验状态、可管理域名数、被几张证书引用
- 「测试连接」结果落库
- 「查看域名」列出账号下真实存在的域名，可**一键用该域名申请证书**
- 覆盖凭据只需填要改的字段；被证书引用时禁止删除并列出证书名

#### 3.4 解析查询与体检

- **多 DNS 并排查询**：一次同时打系统 DNS + 阿里云 / 腾讯云 / Google / Cloudflare 公共 DNS（可勾选、可自定义），并排展示响应码、答案、耗时与差异
- 支持 `A / AAAA / CNAME / TXT / NS / SOA / MX / CAA`，可开关「跟随 CNAME」看链尾真实记录
- **一键体检**六条：NS 委派、权威 NS 可解析、区域顶点 NS 查询、SOA 一致性、多 DNS 一致性、`_acme-challenge` 形态 —— 每条给出「通过 / 注意 / 失败 + 建议」
- 会识别权威 NS 解析到 `198.18.x.x` 这类保留地址（Clash / Surge **fake-ip 劫持**），这类环境签发必然失败
- 全程只读，不创建、不修改任何解析记录

---

## 🕳 DNS-01 踩坑记录

这几个坑都真实踩过，应用里做了针对性处理；若你也在飞牛上签证书失败，多半是其中之一。

<details>
<summary><b>① <code>*</code> 通配 CNAME 把 <code>_acme-challenge</code> 带走 —— <code>No TXT record found</code></b></summary>

若 DNS 里有 `* CNAME 主域名`，`_acme-challenge.<域名>` 也会被 CNAME 指走。按 **RFC 1034**，
一个名字一旦有 CNAME，同名其他类型的记录会被所有合规解析器忽略 —— CA 只会跟着 CNAME 去目标名取 TXT。

DNSPod 允许你在带 CNAME 的名字上再建 TXT，于是「记录明明在」，但 CA 读不到。

**本应用的处理**：通过 DNS 服务商的**记录接口**判断 `_acme-challenge` 是否被 CNAME（含 `*` 通配）覆盖
—— 不看本机 DNS，避免被 NAS 上的 fake-ip / 广告过滤带偏；随后把 TXT 写到 CNAME 目标名，
并在任务日志写明落点：

```
TXT 落点：_acme-challenge.example.com 有 CNAME（通常是 * 通配记录）→ example.com；TXT 写到 example.com
TXT 记录已可被解析到（223.5.5.5:53）：_acme-challenge.example.com
```

</details>

<details>
<summary><b>② 区域顶点 NS 查询空 Answer —— <code>could not determine authoritative nameservers</code></b></summary>

部分 DNS（DNSPod 免费版）对区域顶点的 `NS` 查询只返回 authority 段的 SOA，Answer 为空，
lego 会一直等到超时。本应用在提交 CA **之前**先探测，命中就自动切到「递归解析校验」，
并在日志写一行：

```
传播校验：递归解析；区域 example.com；权威 NS（来自 SOA）：f1g1ns1.dnspod.net
```

也可在「设置 → DNS 传播校验方式」改回 `严格`，或自定义探测用的 DNS 服务器。

</details>

<details>
<summary><b>③ 域名不在账号下 / 凭据错误 —— <code>写入 DNS TXT 记录失败</code></b></summary>

下单前的只读预检会先核对域名是否托管在该账号，不通过就直接说明，而不是等 CA 下单后才报一句
「请检查 API 凭据」。失败时打开任务详情看「错误详情」一行，里面是服务商原始 message + 错误码。

</details>

<details>
<summary><b>④ 其它排查顺序</b></summary>

1. 看任务日志有没有 `TXT 落点` 与 `TXT 记录已可被解析到` 两行 —— 前者是位置，后者是生效；
2. 只有前者没有后者：DNS 传播没跟上，等 1 分钟重试；
3. 到「域名解析」页点「一键体检」，第 2 条看 fake-ip，第 6 条看 CNAME 落点；
4. 调试阶段建议用 **Staging** 环境，避免撞生产速率限制。

</details>

---

## 🔒 安全

- 管理面仅经统一网关 Unix Socket，**不监听管理 TCP 端口**
- 同源校验 + 写操作 CSRF Token
- 私钥与 DNS 凭据隔离在 `secrets/`（`0700` / `0600`），不进配置文件、不进 API 响应、不进日志

### 权限模型

应用以 `root` 启动，**唯一目的**是拿到 `cap_net_bind_service` 以绑定 80/443 等低端口；
启动后立即通过 `runuser` 降权为应用用户 `fngate` 运行，**进程本身不是 root**。
若环境不支持文件能力（xattr），会安全退回以 root 运行，功能不缺失。

系统证书仅被**复制**为应用私有快照，绝不回写系统证书库。

---

## 📦 安装

1. 下载 [Release](https://github.com/HackettMX/fnGate/releases) 里的 `fngate-<版本>.fpk`
2. 飞牛 **应用中心 → 设置 → 手动安装**，上传该文件
3. 安装完成后从桌面图标打开（走飞牛统一网关）

**前置条件**

- 路由器开启 **UPnP**（端口转发功能需要）
- 绑定 80/443 需要 `cap_net_bind_service`（安装脚本自动处理）
- 申请泛域名证书需要对应 DNS 服务商的 API 凭据，或使用「手动 TXT」验证

---

## 🛠 开发

### 本地调试

```bash
cd src
export PATH=/c/Go/bin:$PATH     # 或你的 Go 路径
go run . --web-port 9583        # 不设 FNGATE_SOCKET 即为本地 TCP 调试模式
# 打开 http://127.0.0.1:9583
```

封装脚本：`bash scripts/dev.sh 9583`

### 测试与构建

```bash
cd src
go vet ./...
go test ./...

# 打包三架构 .fpk（需要 .tools/fnpack 与 python3）
bash scripts/build.sh 1.2.3
# 产物：dist/fngate-1.2.3.fpk
```

### 目录结构

```
src/            Go 模块：main + api + core + forward + proxy + cert + acme
  acme/         ACME 客户端、DNS-01 provider（含自研 DNSPod）、解析查询与体检
fpk/            飞牛应用包源：manifest / cmd / config / app/ui / wizard / 图标
scripts/        构建（build.sh）、本地调试（dev.sh）、.fpk 权限修正（fix_fpk_perms.py）
.github/        CI：go vet/test → 三架构交叉编译 → fnpack 打包 → GitHub Release
docs/           设计方案、开发计划、模块重构方案、上架材料
```

### 自动发布

推送 `v*` 标签或手动触发 `workflow_dispatch`，CI 会自动完成
**静态检查 → 测试 → 三架构编译 → 打 `.fpk` → 发布 Release**。

```bash
git tag v1.2.3 && git push origin v1.2.3
```

---

## 📋 版本

| 版本 | 主要变化 |
|---|---|
| **1.2.3** | 修复 `_acme-challenge` 被 `*` 通配 CNAME 覆盖时 TXT 写错位置；CNAME 判定改查服务商记录接口 |
| 1.2.2 | 名称调整：路由转发 / 域名解析 / 证书申请；CNAME 逐跳跟随 |
| 1.2.x | 证书库按来源分 tab + 状态筛选；域名解析与体检合并 |
| 1.0.0 | 首个版本：路由转发、反向代理、证书管理 |

完整更新日志见 [`docs/上架材料.md`](docs/上架材料.md)。

---

## 📄 许可证

本项目供飞牛 fnOS 使用，请遵循仓库许可证与飞牛应用商店相关规范。
