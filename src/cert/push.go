package cert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"fngate/cert/deployer"
)

// pushClient 是降权主应用访问 root 部署守护的客户端（HTTP over Unix Socket）。
type pushClient struct {
	socket string
	client *http.Client
}

func newPushClient(socket string) *pushClient {
	if strings.TrimSpace(socket) == "" {
		socket = deployer.DefaultSock
	}
	return &pushClient{
		socket: socket,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
			// 单次调用的超时由 callT 控制：部署要重启飞牛服务，耗时可能超过两分钟。
			Timeout: 0,
		},
	}
}

// pushError 携带从守护返回的错误码与阶段。
type pushError struct {
	Code   string `json:"code"`
	Stage  string `json:"stage"`
	Msg    string `json:"error"`
	Detail string `json:"detail"`
}

func (e *pushError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return deployer.Text(deployer.Code(e.Code))
}

type pushTargetsResp struct {
	deployer.StatusResult
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`
}

// callT 给单次调用设置独立超时（父 ctx 更早截止时以父为准）。
func (c *pushClient) callT(ctx context.Context, d time.Duration, path string, in interface{}, out interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return c.call(ctx, path, in, out)
}

func (c *pushClient) call(ctx context.Context, path string, in interface{}, out interface{}) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s", deployer.Text(deployer.CodeUnavailable))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var pe pushError
		if json.Unmarshal(raw, &pe) == nil && pe.Msg != "" {
			return &pe
		}
		return fmt.Errorf("部署服务返回 HTTP %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("部署服务响应解析失败：%v", err)
		}
	}
	return nil
}

func (c *pushClient) Status(ctx context.Context) (*deployer.StatusResult, error) {
	var out pushTargetsResp
	if err := c.callT(ctx, 10*time.Second, "/status", struct{}{}, &out); err != nil {
		return nil, err
	}
	res := out.StatusResult
	return &res, nil
}

func (c *pushClient) Prepare(ctx context.Context, in deployer.PrepareInput) (*deployer.PrepareResult, error) {
	var out deployer.PrepareResult
	if err := c.callT(ctx, 90*time.Second, "/prepare", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *pushClient) Deploy(ctx context.Context, in deployer.PrepareInput) (*deployer.DeployResult, error) {
	var out deployer.DeployResult
	// 部署要写文件、重启飞牛服务并做 TLS 验证，按 5 分钟给足余量，
	// 避免主应用先超时、而守护仍在执行时用户重试被「正在运行」挡住。
	if err := c.callT(ctx, 300*time.Second, "/deploy", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// probe 探测守护是否在线，并保留失败原因（用于界面诊断）。
func (c *pushClient) probe(ctx context.Context) error {
	_, err := c.Status(ctx)
	return err
}

// Repair 请求守护归档「上次同步未完成」的残留记录。
func (c *pushClient) Repair(ctx context.Context) (*deployer.RepairResult, error) {
	var out deployer.RepairResult
	if err := c.callT(ctx, 120*time.Second, "/repair", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
