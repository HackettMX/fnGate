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
			Timeout: 120 * time.Second,
		},
	}
}

// pushError 携带从守护返回的错误码与阶段。
type pushError struct {
	Code  string `json:"code"`
	Stage string `json:"stage"`
	Msg   string `json:"error"`
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
	if err := c.call(ctx, "/status", struct{}{}, &out); err != nil {
		return nil, err
	}
	res := out.StatusResult
	return &res, nil
}

func (c *pushClient) Prepare(ctx context.Context, in deployer.PrepareInput) (*deployer.PrepareResult, error) {
	var out deployer.PrepareResult
	if err := c.call(ctx, "/prepare", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *pushClient) Deploy(ctx context.Context, in deployer.PrepareInput) (*deployer.DeployResult, error) {
	var out deployer.DeployResult
	if err := c.call(ctx, "/deploy", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// deployAvailable 快速探测守护是否在线。
func (c *pushClient) deployAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Status(ctx)
	return err == nil
}
