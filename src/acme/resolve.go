package acme

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// 域名解析查询与体检（P2）。
//
// 这块能力与签发链路共用同一套探测实现（dnsExchange / findZone / apexNameservers），
// 目的就是让「签发失败时看到的东西」和「这里看到的东西」是同一份事实，
// 而不是用户在两个工具之间对不上。

// resolveRecordTypes 是前端下拉支持的记录类型，顺序即展示顺序。
var resolveRecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "NS", "SOA", "MX", "CAA"}

// presetResolvers 是「服务器」多选里的公共 DNS 候选。
var presetResolvers = []struct {
	Server string `json:"server"`
	Label  string `json:"label"`
}{
	{"223.5.5.5:53", "阿里云公共 DNS"},
	{"119.29.29.29:53", "腾讯云公共 DNS"},
	{"8.8.8.8:53", "Google DNS"},
	{"1.1.1.1:53", "Cloudflare DNS"},
}

func resolveQType(t string) (uint16, error) {
	up := strings.ToUpper(strings.TrimSpace(t))
	if up == "" {
		up = "A"
	}
	for _, name := range resolveRecordTypes {
		if name == up {
			return dns.StringToType[up], nil
		}
	}
	return 0, fmt.Errorf("不支持的记录类型：%s（可选 %s）", t, strings.Join(resolveRecordTypes, " / "))
}

// normalizeQueryName 把用户可能粘贴的整段 URL / 通配域名收拾成纯域名。
func normalizeQueryName(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", fmt.Errorf("请输入要查询的域名")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:] // 粘贴成邮箱形式时取 @ 后面的域名
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	for _, r := range s {
		switch {
		case r == '.' || r == '-' || r == '_':
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r > 127:
			return "", fmt.Errorf("暂不支持非 ASCII 域名，请填写 punycode（xn--）形式")
		default:
			return "", fmt.Errorf("域名含非法字符：%q", string(r))
		}
	}
	if !strings.Contains(s, ".") {
		return "", fmt.Errorf("%s 不是完整域名，请填写形如 example.com 的完整域名", s)
	}
	return s, nil
}

// humanizeDNSErr 把网络层错误翻成用户能判断原因的话。
func humanizeDNSErr(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"):
		return "无响应（超时，可能被防火墙拦截）"
	case strings.Contains(s, "connection refused"):
		return "连接被拒绝（该服务器未提供 53 端口服务）"
	case strings.Contains(s, "no such host"):
		return "服务器域名无法解析"
	case strings.Contains(s, "network is unreachable"), strings.Contains(s, "no route to host"):
		return "网络不可达"
	}
	return err.Error()
}

// resolveAnswer 是一台 DNS 服务器对单次查询的完整回答。
type resolveAnswer struct {
	Server    string   `json:"server"`
	RCode     string   `json:"rcode"`
	Answers   []string `json:"answers"`
	Authority []string `json:"authority"`
	ElapsedMS int64    `json:"elapsed_ms"`
	Error     string   `json:"error"`
	Truncated bool     `json:"truncated"`
}

func queryOne(server, name string, qtype uint16) resolveAnswer {
	res := resolveAnswer{Server: server, Answers: []string{}, Authority: []string{}}
	start := time.Now()
	resp, err := dnsExchange(server, name, qtype)
	res.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		res.RCode = "ERROR"
		res.Error = humanizeDNSErr(err)
		return res
	}
	res.RCode = dns.RcodeToString[resp.Rcode]
	res.Truncated = resp.Truncated
	for _, rr := range resp.Answer {
		res.Answers = append(res.Answers, strings.Join(strings.Fields(rr.String()), " "))
	}
	for _, rr := range resp.Ns {
		res.Authority = append(res.Authority, strings.Join(strings.Fields(rr.String()), " "))
	}
	return res
}

// queryEach 并发打多台 DNS，保证结果按传入顺序排列，便于并排对比。
func queryEach(servers []string, name string, qtype uint16) []resolveAnswer {
	out := make([]resolveAnswer, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			out[i] = queryOne(server, name, qtype)
		}(i, s)
	}
	wg.Wait()
	return out
}

func answerSignature(res resolveAnswer) string {
	if res.Error != "" {
		return "ERR:" + res.Error
	}
	items := append([]string(nil), res.Answers...)
	sort.Strings(items)
	return res.RCode + "|" + strings.Join(items, ";")
}

// summarizeConsistency 判断多台 DNS 的回答是否一致，并给出一句人话。
func summarizeConsistency(results []resolveAnswer) (bool, string) {
	valid := make([]resolveAnswer, 0, len(results))
	for _, r := range results {
		if r.Error == "" {
			valid = append(valid, r)
		}
	}
	if len(valid) <= 1 {
		return true, fmt.Sprintf("只有 %d 台服务器给出有效响应，无法比对一致性", len(valid))
	}
	base := answerSignature(valid[0])
	same := 1
	for _, r := range valid[1:] {
		if answerSignature(r) == base {
			same++
		}
	}
	if same == len(valid) {
		return true, fmt.Sprintf("%d 台服务器结果完全一致", len(valid))
	}
	return false, fmt.Sprintf("%d/%d 台结果不一致，可能仍在传播或存在分线路解析", len(valid)-same, len(valid))
}

// cnameChain 从回答里按出现顺序抽出 CNAME 链（同名去重）。
func cnameChain(results []resolveAnswer) []string {
	var chain []string
	seen := map[string]bool{}
	for _, r := range results {
		for _, line := range r.Answers {
			fields := strings.Fields(line)
			if len(fields) < 5 || !strings.EqualFold(fields[3], "CNAME") {
				continue
			}
			src := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
			dst := strings.TrimSuffix(strings.ToLower(fields[4]), ".")
			if !seen[src] {
				seen[src] = true
				chain = append(chain, src)
			}
			if !seen[dst] {
				seen[dst] = true
				chain = append(chain, dst)
			}
		}
	}
	return chain
}

type resolveResult struct {
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Results    []resolveAnswer `json:"results"`
	Chain      []string        `json:"chain"`
	FinalName  string          `json:"final_name"`
	Consistent bool            `json:"consistent"`
	Summary    string          `json:"summary"`
	ElapsedMS  int64           `json:"elapsed_ms"`
}

// runResolveQuery 执行一次多服务器查询。
//
// follow 为真时，如果回答里只有 CNAME 而没有目标类型的记录，
// 会再对链尾名字查一次同类型并追加到答案里，对应界面上的「跟随 CNAME」。
func runResolveQuery(name, typ string, servers []string, follow bool) (resolveResult, error) {
	start := time.Now()
	clean, err := normalizeQueryName(name)
	if err != nil {
		return resolveResult{}, err
	}
	qtype, err := resolveQType(typ)
	if err != nil {
		return resolveResult{}, err
	}
	if len(servers) == 0 {
		return resolveResult{}, fmt.Errorf("请至少选择一台 DNS 服务器")
	}
	servers = normalizeResolvers(servers)
	if len(servers) > 8 {
		servers = servers[:8] // 并发上限，避免误配几十台把 NAS 打满
	}

	out := resolveResult{Name: clean, Type: strings.ToUpper(strings.TrimSpace(typ)), Results: queryEach(servers, clean, qtype)}
	if strings.TrimSpace(typ) == "" {
		out.Type = "A"
	}
	out.Chain = cnameChain(out.Results)

	if follow && len(out.Chain) > 0 {
		target := out.Chain[len(out.Chain)-1]
		if target != clean {
			out.FinalName = target
			extra := queryEach(servers, target, qtype)
			for i := range out.Results {
				if out.Results[i].Error != "" {
					continue
				}
				// 只有「没有目标类型记录」的服务器才需要补查，避免重复展示。
				if hasTypeAnswer(out.Results[i].Answers, qtype) {
					continue
				}
				if extra[i].Error == "" {
					out.Results[i].Answers = append(out.Results[i].Answers, extra[i].Answers...)
					out.Results[i].ElapsedMS += extra[i].ElapsedMS
				}
			}
		}
	}

	out.Consistent, out.Summary = summarizeConsistency(out.Results)
	out.ElapsedMS = time.Since(start).Milliseconds()
	return out, nil
}

func hasTypeAnswer(answers []string, qtype uint16) bool {
	want := dns.TypeToString[qtype]
	for _, line := range answers {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.EqualFold(fields[3], want) {
			return true
		}
	}
	return false
}

// ---------- 体检 ----------

const (
	checkPass = "pass"
	checkWarn = "warn"
	checkFail = "fail"
	checkSkip = "skip"
)

type checkItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Advice string `json:"advice"`
}

type diagnoseResult struct {
	Domain      string      `json:"domain"`
	Zone        string      `json:"zone"`
	NameServers []string    `json:"nameservers"`
	NSource     string      `json:"ns_source"`
	Servers     []string    `json:"servers"`
	Checks      []checkItem `json:"checks"`
	PassCount   int         `json:"pass_count"`
	WarnCount   int         `json:"warn_count"`
	FailCount   int         `json:"fail_count"`
	Verdict     string      `json:"verdict"`
	ElapsedMS   int64       `json:"elapsed_ms"`
}

// runDiagnose 对域名跑 6 条检查。
//
// 每条都独立给出结论，不因为前面失败就整体中断——用户最需要的往往是
// 「到底哪一步不对」，而不是一个笼统的失败。
func runDiagnose(domain string, servers []string) (diagnoseResult, error) {
	start := time.Now()
	clean, err := normalizeQueryName(domain)
	if err != nil {
		return diagnoseResult{}, err
	}
	if len(servers) == 0 {
		return diagnoseResult{}, fmt.Errorf("请至少选择一台 DNS 服务器")
	}
	servers = normalizeResolvers(servers)

	out := diagnoseResult{Domain: clean, Servers: servers, Checks: make([]checkItem, 0, 6)}

	zone, zoneErr := findZone(clean, servers)
	out.Zone = zone
	if zoneErr != nil {
		out.Checks = append(out.Checks, checkItem{
			ID: "ns_delegation", Name: "NS 委派", Status: checkFail,
			Detail: "无法确定域名所属区域：" + zoneErr.Error(),
			Advice: "确认域名已注册且 NS 已指向某个 DNS 服务商；新注册域名通常需要几分钟到几小时生效",
		})
		for _, rest := range []struct{ id, name string }{
			{"ns_resolvable", "权威 NS 可解析"}, {"apex_ns_answer", "区域顶点 NS 查询"},
			{"soa_consistency", "SOA 一致性"}, {"resolver_consistency", "多 DNS 一致性"},
			{"acme_challenge", "_acme-challenge 形态"},
		} {
			out.Checks = append(out.Checks, checkItem{ID: rest.id, Name: rest.name, Status: checkSkip, Detail: "区域未知，跳过"})
		}
		out.finish(start)
		return out, nil
	}

	ns, nsource, nsErr := apexNameservers(zone, servers)
	out.NameServers, out.NSource = ns, nsource

	// 1) NS 委派
	out.Checks = append(out.Checks, checkNSDelegation(zone, ns, nsource, nsErr))
	// 2) 权威 NS 可解析
	out.Checks = append(out.Checks, checkNSResolvable(ns, servers, nsErr))
	// 3) 区域顶点 NS 查询（v1.0.1 的坑）
	out.Checks = append(out.Checks, checkApexNSAnswer(zone, servers, nsErr, nsource))
	// 4) SOA 一致性
	out.Checks = append(out.Checks, checkSOAConsistency(zone, servers))
	// 5) 多 DNS 一致性
	out.Checks = append(out.Checks, checkResolverConsistency(zone, servers))
	// 6) _acme-challenge 形态（v1.0.1 的另一个坑）
	out.Checks = append(out.Checks, checkACMEName(zone, servers))

	out.finish(start)
	return out, nil
}

func (d *diagnoseResult) finish(start time.Time) {
	for _, c := range d.Checks {
		switch c.Status {
		case checkPass:
			d.PassCount++
		case checkWarn:
			d.WarnCount++
		case checkFail:
			d.FailCount++
		}
	}
	switch {
	case d.FailCount > 0:
		d.Verdict = "存在会阻断签发的问题，建议先按提示处理"
	case d.WarnCount > 0:
		d.Verdict = "可以签发，但有需要注意的点"
	default:
		d.Verdict = "全部通过，域名解析状态适合签发"
	}
	d.ElapsedMS = time.Since(start).Milliseconds()
}

func checkNSDelegation(zone string, ns []string, source string, nsErr error) checkItem {
	item := checkItem{ID: "ns_delegation", Name: "NS 委派"}
	if nsErr != nil {
		item.Status = checkFail
		item.Detail = fmt.Sprintf("无法获取 %s 的权威 NS：%v", zone, nsErr)
		item.Advice = "确认域名的 NS 记录已指向当前 DNS 服务商；域名刚注册或刚改 NS 时需要等待生效"
		return item
	}
	item.Status = checkPass
	item.Detail = fmt.Sprintf("%s 的权威 NS：%s", zone, strings.Join(ns, "、"))
	if source == "SOA" {
		item.Status = checkWarn
		item.Detail = fmt.Sprintf("NS 查询未返回 Answer，从 SOA 推得主权威服务器：%s", strings.Join(ns, "、"))
		item.Advice = "该 DNS 不按 RFC 返回 apex NS（DNSPod 常见）。签发时保持「传播校验方式 = 自动」即可，系统会自动降级为递归校验"
		return item
	}
	if len(ns) == 1 {
		item.Status = checkWarn
		item.Detail += "（只有 1 台）"
		item.Advice = "建议至少配置 2 台权威 NS，避免单点故障导致 CA 校验失败"
	}
	return item
}

func checkNSResolvable(ns []string, servers []string, nsErr error) checkItem {
	item := checkItem{ID: "ns_resolvable", Name: "权威 NS 可解析"}
	if nsErr != nil || len(ns) == 0 {
		item.Status = checkSkip
		item.Detail = "权威 NS 未知，跳过"
		return item
	}
	var okParts, badParts, hijacked []string
	for _, host := range ns {
		resp, _, err := firstResolverAnswer(servers, host, dns.TypeA)
		if err == nil && len(resp.Answer) > 0 {
			ips := make([]string, 0, len(resp.Answer))
			for _, rr := range resp.Answer {
				if a, isA := rr.(*dns.A); isA {
					ips = append(ips, a.A.String())
				}
			}
			if len(ips) > 0 {
				okParts = append(okParts, host+" → "+strings.Join(ips, "/"))
				for _, s := range ips {
					if isHijackedIP(net.ParseIP(s)) {
						hijacked = append(hijacked, host+" → "+s)
					}
				}
				continue
			}
		}
		// 只有 AAAA 的权威服务器也存在，补一次。
		if resp6, _, err6 := firstResolverAnswer(servers, host, dns.TypeAAAA); err6 == nil && len(resp6.Answer) > 0 {
			okParts = append(okParts, host+" → IPv6")
			continue
		}
		badParts = append(badParts, host)
	}
	item.Detail = strings.Join(okParts, "；")
	switch {
	case len(okParts) == 0:
		item.Status = checkFail
		item.Detail = "以下权威 NS 无法解析出 IP：" + strings.Join(badParts, "、")
		item.Advice = "权威服务器域名解析失败时 CA 一定校验不过，请联系 DNS 服务商"
	case len(hijacked) > 0:
		item.Status = checkWarn
		item.Detail += "；其中 " + strings.Join(hijacked, "、") + " 属于保留地址段"
		item.Advice = "权威 NS 解析到 198.18.x.x / 0.0.0.0 这类保留地址，通常是本机 DNS 被代理软件（Clash / Surge 的 fake-ip 模式）劫持。CA 校验时会连到假地址而失败，建议让 NAS 的 53 端口查询直连或关闭 fake-ip"
	case len(badParts) > 0:
		item.Status = checkWarn
		item.Detail += "；无法解析：" + strings.Join(badParts, "、")
		item.Advice = "部分权威 NS 解析异常，CA 仍可从正常的 NS 校验，但建议排查"
	default:
		item.Status = checkPass
	}
	return item
}

// isHijackedIP 识别被代理软件 fake-ip 模式占用的保留地址。
// 198.18.0.0/15 是 RFC 2544 的测试段，Clash / Surge 默认拿它当假 IP。
func isHijackedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
		return true
	}
	return false
}

// checkApexNSAnswer 是 v1.0.1 报错的直接检查项。
func checkApexNSAnswer(zone string, servers []string, nsErr error, source string) checkItem {
	item := checkItem{ID: "apex_ns_answer", Name: "区域顶点 NS 查询"}
	results := queryEach(servers, zone, dns.TypeNS)
	withAnswer, empty, failed := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Error != "":
			failed++
		case hasTypeAnswer(r.Answers, dns.TypeNS):
			withAnswer++
		default:
			empty++
		}
	}
	switch {
	case withAnswer == len(results):
		item.Status = checkPass
		item.Detail = fmt.Sprintf("%d 台服务器都返回了 NS 记录", withAnswer)
	case empty > 0 && withAnswer == 0:
		item.Status = checkWarn
		item.Detail = fmt.Sprintf("%d 台服务器对 %s 的 NS 查询返回空 Answer（仅 authority 段 SOA），%d 台请求失败", empty, zone, failed)
		item.Advice = "这正是 could not determine authoritative nameservers 的成因。签发时把「传播校验方式」保持为自动或改为递归即可，无需改 DNS"
	case empty > 0 || failed > 0:
		item.Status = checkWarn
		item.Detail = fmt.Sprintf("%d 台有 Answer，%d 台为空，%d 台失败（存在分线路解析或缓存差异）", withAnswer, empty, failed)
		item.Advice = "签名前建议在设置里把「自定义 DNS 服务器」固定为国内公共 DNS"
	default:
		item.Status = checkFail
		item.Detail = "所有服务器都没能完成 NS 查询"
		item.Advice = "检查 NAS 到 53 端口的出网是否被拦截"
	}
	if item.Status == checkWarn && source == "SOA" && nsErr == nil {
		item.Advice = "该 DNS 不回 apex NS（DNSPod 常见），系统已支持自动降级；保持「传播校验方式 = 自动」即可"
	}
	return item
}

func checkSOAConsistency(zone string, servers []string) checkItem {
	item := checkItem{ID: "soa_consistency", Name: "SOA 一致性"}
	results := queryEach(servers, zone, dns.TypeSOA)
	serials := map[string][]string{}
	var detail []string
	for _, r := range results {
		for _, line := range r.Answers {
			fields := strings.Fields(line)
			if len(fields) < 7 || !strings.EqualFold(fields[3], "SOA") {
				continue
			}
			serial := fields[6]
			serials[serial] = append(serials[serial], r.Server)
			detail = append(detail, fmt.Sprintf("%s: serial %s", r.Server, serial))
		}
	}
	if len(serials) == 0 {
		item.Status = checkWarn
		item.Detail = "所有服务器都没有返回 SOA 记录"
		item.Advice = "确认区域是否存在；未托管在公网 DNS 的内网域名属正常现象"
		return item
	}
	if len(serials) == 1 {
		item.Status = checkPass
		for serial := range serials {
			item.Detail = fmt.Sprintf("%d 台服务器 SOA 序列号一致：%s", len(results), serial)
		}
		return item
	}
	item.Status = checkWarn
	item.Detail = "各服务器 SOA 序列号不一致（" + strings.Join(detail, "；") + "）"
	item.Advice = "说明记录改动尚未同步到所有服务器，稍等几分钟再查"
	return item
}

func checkResolverConsistency(zone string, servers []string) checkItem {
	item := checkItem{ID: "resolver_consistency", Name: "多 DNS 一致性"}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeTXT} {
		results := queryEach(servers, zone, qtype)
		hasAny := false
		for _, r := range results {
			if len(r.Answers) > 0 {
				hasAny = true
				break
			}
		}
		if !hasAny {
			continue
		}
		same, summary := summarizeConsistency(results)
		item.Detail = fmt.Sprintf("%s 的 %s 记录：%s", zone, dns.TypeToString[qtype], summary)
		if same {
			item.Status = checkPass
			return item
		}
		item.Status = checkWarn
		item.Advice = "部分 DNS 仍有旧缓存。签发时系统会等 TXT 传播，一般不影响；持续不一致请检查是否配置了分线路解析"
		return item
	}
	item.Status = checkSkip
	item.Detail = fmt.Sprintf("%s 没有 A / TXT 记录可比对", zone)
	return item
}

// checkACMEName 对应 v1.0.1「no subdomain because the domain and the zone are identical」的成因。
func checkACMEName(zone string, servers []string) checkItem {
	item := checkItem{ID: "acme_challenge", Name: "_acme-challenge 形态"}
	name := "_acme-challenge." + zone
	resp, _, err := firstResolverAnswer(servers, name, dns.TypeCNAME)
	if err != nil {
		item.Status = checkPass
		item.Detail = fmt.Sprintf("%s 暂无记录（签发时会自动创建），或该 DNS 对不存在的名字返回非 NOERROR", name)
		return item
	}
	var target string
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			target = strings.TrimSuffix(strings.ToLower(c.Target), ".")
			break
		}
	}
	switch {
	case target == "":
		item.Status = checkPass
		item.Detail = fmt.Sprintf("%s 没有 CNAME，TXT 会写在这个名字上", name)
	case target == zone:
		item.Status = checkWarn
		item.Detail = fmt.Sprintf("%s 是 CNAME → %s（通配 CNAME 的典型表现），CA 只认 %s 上的 TXT%s",
			name, target, target, txtPresence(servers, target))
		item.Advice = "签发时已自动把 TXT 写在这个目标名上，无需手工干预；若希望 _acme-challenge 有独立记录，可删除 DNS 里的 * 通配 CNAME"
	default:
		item.Status = checkWarn
		item.Detail = fmt.Sprintf("%s 是 CNAME → %s，CA 只会去该目标名取 TXT%s",
			name, target, txtPresence(servers, target))
		item.Advice = "确认目标域名也在你配置的 DNS 服务商账号下，否则签发时写不进 TXT"
	}
	return item
}

// txtPresence 返回「该名字当前有几条 TXT」的说明，用来在体检页确认记录落点。
func txtPresence(servers []string, name string) string {
	resp, _, err := firstResolverAnswer(servers, name, dns.TypeTXT)
	if err != nil || resp == nil {
		return "（该名下暂时读不到 TXT）"
	}
	n := 0
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.TXT); ok {
			n++
		}
	}
	if n == 0 {
		return "（该名下暂时读不到 TXT，签发时会自动写入）"
	}
	return fmt.Sprintf("（该名下当前有 %d 条 TXT）", n)
}
