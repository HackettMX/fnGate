package deployer

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// plan 做完整预检并生成部署 journal，不修改任何系统状态。
func (e *Engine) plan(input PrepareInput) (*journal, *targetInfo, *parsedCert, error) {
	if _, err := strconvAtoiPositive(input.TargetID); err != nil ||
		!validDomainName(input.ProbeHost) || strings.HasPrefix(input.ProbeHost, "*.") ||
		!validPort(input.ProbePort) {
		return nil, nil, nil, fail(CodeInvalid)
	}

	st, err := e.read()
	if err != nil {
		return nil, nil, nil, err
	}
	var row certRow
	for _, r := range st.Rows {
		if rowString(r, "id") == input.TargetID {
			row = r
			break
		}
	}
	t, err := e.target(row, st)
	if err != nil {
		return nil, nil, nil, err
	}
	next, err := inspectCertificate([]byte(input.CertificatePEM), []byte(input.PrivateKeyPEM), false)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := assertPublicTrust(next); err != nil {
		return nil, nil, nil, err
	}
	if !equalJSON(next.Domains, t.Parsed.Domains) || !domainCovered(next, input.ProbeHost) {
		return nil, nil, nil, fail(CodeDomain)
	}
	if input.ExpectedFingerprint != "" && !sameFingerprint(input.ExpectedFingerprint, t.Parsed.Fingerprint) {
		return nil, nil, nil, fail(CodeConflict)
	}

	// 网关映射必须绑定该证书，且 host 为 fallback / 探测域名 / 证书域名之一。
	mapped := false
	for _, m := range st.Mappings {
		if m.Cert == rowString(t.Row, "certificate") && m.Key == rowString(t.Row, "private_key") &&
			(m.Host == "fallback" || m.Host == input.ProbeHost || contains(t.Parsed.Domains, m.Host)) {
			mapped = true
			break
		}
	}
	if !mapped {
		return nil, nil, nil, failDetail(CodeIncompatible, "mapping",
			fmt.Sprintf("network_gateway_cert.conf 共 %d 条映射，没有一条把这张证书绑定到 HTTPS 服务；"+
				"请先在飞牛「系统设置 → 安全性 → 证书 → 服务配置」里选择它", len(st.Mappings)))
	}

	// 部署前用旧证书指纹探测本机 HTTPS，确认目标当前在线。
	if err := probeTLS(input.ProbeHost, input.ProbePort, t.Parsed.Fingerprint, false); err != nil {
		return nil, nil, nil, err
	}

	mode, gid, err := keyPermissions()
	if err != nil || mode != 0o640 || gid <= 0 {
		return nil, nil, nil, fail(CodeIncompatible)
	}

	// 文件写入清单：目标证书、目标私钥（私钥改权限 0640/ www-data 组），
	// 以及 issuer_certificate、fullchain、fullchain.crt 等旁证文件。
	files := []*fileSnapshot{
		{File: t.Cert.File, Content: t.Cert.Content, Mode: t.Cert.Mode, UID: t.Cert.UID, GID: t.Cert.GID, IsCert: true,
			Next: b64(next.ChainPEM)},
		{File: t.Key.File, Content: t.Key.Content, Mode: t.Key.Mode, UID: t.Key.UID, GID: t.Key.GID, IsCert: true,
			Next: b64([]byte(input.PrivateKeyPEM)), NextMode: mode, NextGID: gid},
	}

	issuerPath := rowString(t.Row, "issuer_certificate")
	type extra struct {
		path      string
		pem       []byte
		fullchain bool
		required  bool
	}
	extras := []extra{
		{path: issuerPath, pem: next.IssuerPEM, required: true},
		{path: t.Entry.Fullchain, pem: next.ChainPEM, fullchain: true, required: true},
		{path: filepath.Join(filepath.Dir(t.Cert.File), "fullchain.crt"), pem: next.ChainPEM, fullchain: true},
	}
	for _, x := range extras {
		if x.path == "" || pathIn(files, x.path) {
			continue
		}
		if _, err := os.Lstat(x.path); err != nil {
			if x.required {
				return nil, nil, nil, fail(CodeIncompatible)
			}
			continue
		}
		snap, err := e.snapshot(x.path, true)
		if err != nil {
			return nil, nil, nil, err
		}
		if x.fullchain {
			p, err := inspectCertificate(mustB64(snap.Content), []byte(input.PrivateKeyPEM), true)
			if err != nil {
				return nil, nil, nil, failDetail(CodeIncompatible, "fullchain",
					fmt.Sprintf("现有链文件 %s 无法解析：%s", x.path, detailOf(err)))
			}
			if !sameFingerprint(p.Fingerprint, t.Parsed.Fingerprint) {
				return nil, nil, nil, failDetail(CodeIncompatible, "fullchain",
					fmt.Sprintf("现有链文件 %s 的叶子证书（%s）与数据库记录的证书（%s）不一致，"+
						"说明 fnOS 里这张证书的文件已被其它操作改动，请重新导入后再同步", x.path, p.Fingerprint, t.Parsed.Fingerprint))
			}
		}
		files = append(files, &fileSnapshot{File: x.path, Content: snap.Content, Mode: snap.Mode,
			UID: snap.UID, GID: snap.GID, IsCert: true, Next: b64(x.pem)})
	}

	// 唯一性：其它证书行/索引条目不得引用这些文件。
	for _, r := range st.Rows {
		if rowString(r, "id") == t.RowID {
			continue
		}
		for _, f := range []string{rowString(r, "certificate"), rowString(r, "private_key"), rowString(r, "issuer_certificate")} {
			if f != "" && pathIn(files, f) {
				return nil, nil, nil, fail(CodeIncompatible)
			}
		}
	}
	for i, ent := range st.Entries {
		if i == t.EntryIndex {
			continue
		}
		for _, f := range []string{ent.Certificate, ent.PrivateKey, ent.Fullchain} {
			if f != "" && pathIn(files, f) {
				return nil, nil, nil, fail(CodeIncompatible)
			}
		}
	}

	// 索引条目有效期同步更新。
	newEntries := append([]indexEntry(nil), st.Entries...)
	newEntries[t.EntryIndex] = indexEntry{
		Certificate: t.Entry.Certificate, PrivateKey: t.Entry.PrivateKey, Fullchain: t.Entry.Fullchain,
		ValidFrom: jsonNumber(next.ValidFromMS), ValidTo: jsonNumber(next.ValidToMS),
	}
	idxNext := []byte(marshalJSON(newEntries))
	files = append(files, &fileSnapshot{File: e.IndexPath, Content: st.Index.Content,
		Mode: st.Index.Mode, UID: st.Index.UID, GID: st.Index.GID, Next: b64(idxNext)})

	// 数据库行更新后的值（CAS 用整行比较）。
	after := certRow{}
	for k, v := range t.Row {
		after[k] = v
	}
	after["valid_from"] = jsonNumber(next.ValidFromMS)
	after["valid_to"] = jsonNumber(next.ValidToMS)
	after["encrypt_type"] = next.EncryptType
	after["issued_by"] = next.IssuedBy
	after["status"] = "suc"
	after["updated_time"] = jsonNumber(time.Now().UnixMilli())

	validTo := time.UnixMilli(next.ValidToMS).UTC().Format(time.RFC3339)
	planID := sha256Hex([]byte(canonicalJSON(struct {
		Files   []*fileSnapshot
		Row     certRow
		Gateway string
		Host    string
		Port    int
	}{files, t.Row, st.Gateway.Content, input.ProbeHost, input.ProbePort})))

	j := &journal{
		Files: files, RowBefore: t.Row, RowAfter: after,
		Gateway: st.Gateway, ProbeHost: input.ProbeHost, ProbePort: input.ProbePort,
		OldFingerprint: t.Parsed.Fingerprint, NewFingerprint: next.Fingerprint,
		ValidTo: validTo, PlanID: planID,
	}
	return j, t, next, nil
}

// Prepare 只做预检，返回预览信息。
func (e *Engine) Prepare(input PrepareInput, running bool) (*PrepareResult, error) {
	if running {
		return nil, fail(CodeBusy)
	}
	j, t, next, err := e.plan(input)
	if err != nil {
		return nil, err
	}
	// 记住这份计划：用户确认后，/deploy 直接按它执行。
	prepared.put(j)
	return &PrepareResult{
		PlanID: j.PlanID, Target: publicTarget(t, true, input.ProbeHost, nil),
		Fingerprint: next.Fingerprint, ValidTo: j.ValidTo,
		ProbeHost: input.ProbeHost, ProbePort: input.ProbePort, Domains: next.Domains,
	}, nil
}

func strconvAtoiPositive(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid id")
	}
	return n, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func pathIn(files []*fileSnapshot, path string) bool {
	for _, f := range files {
		if f.File == path {
			return true
		}
	}
	return false
}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }
