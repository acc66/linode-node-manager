package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Match wp2 Tools::v2Array: server overrides the first address, relayserver
// overrides server. host/SNI are transport fields and never DNS destinations.
func wp2ConnectionAddress(raw string) (string, error) {
	parts := strings.Split(strings.TrimSpace(raw), ";")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "", errors.New("wp2 没有节点连接地址")
	}
	address := strings.TrimSpace(parts[0])
	extras := ""
	if len(parts) > 1 && strings.Contains(parts[1], "=") {
		extras = parts[1]
	} else if len(parts) > 5 {
		extras = strings.Join(parts[5:], ";")
	}
	options := map[string]string{}
	for _, part := range strings.Split(extras, "|") {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(pair[0]))
		value, err := url.QueryUnescape(pair[1])
		if err != nil {
			return "", errors.New("wp2 连接参数编码无效")
		}
		options[key] = strings.TrimSpace(value)
	}
	if options["server"] != "" {
		address = options["server"]
	}
	if options["relayserver"] != "" {
		address = options["relayserver"]
	}
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil || u.User != nil || u.Hostname() == "" {
			return "", errors.New("wp2 连接地址格式无效")
		}
		address = u.Hostname()
	} else if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	address = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(address), "[]"), "."))
	if net.ParseIP(address) != nil {
		return address, nil
	}
	return normalizeZone(address)
}
func (s *Server) adminWP2Connection(ctx context.Context, session *wp2Session, target int) (string, error) {
	client := s.wp2Client(session)
	for start := 0; start < 10000; start += 100 {
		form := url.Values{"draw": {"1"}, "start": {strconv.Itoa(start)}, "length": {"100"}, "search[value]": {strconv.Itoa(target)}, "order[0][column]": {"0"}, "order[0][dir]": {"asc"}, "columns[0][data]": {"id"}}
		resp, err := wp2Form(ctx, client, session.Base+"/admin/node/ajax", form)
		if err != nil {
			return "", errors.New("无法读取 wp2 节点连接地址")
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			resp.Body.Close()
			return "", errWP2Expired
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return "", fmt.Errorf("wp2 管理接口 HTTP %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				ID     int    `json:"id"`
				Server string `json:"server"`
			} `json:"data"`
			Total *int `json:"recordsFiltered"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result)
		resp.Body.Close()
		if err != nil || result.Total == nil {
			return "", errors.New("wp2 未返回节点原始配置，请重新连接管理员账号")
		}
		for _, node := range result.Data {
			if node.ID == target {
				if node.Server == "" {
					return "", errors.New("wp2 节点连接地址为空")
				}
				return wp2ConnectionAddress(node.Server)
			}
		}
		if start+len(result.Data) >= *result.Total || len(result.Data) == 0 {
			break
		}
	}
	return "", errors.New("wp2 管理列表没有找到指定节点")
}
func (s *Server) legacyWP2Connection(ctx context.Context, base, token string, target int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+fmt.Sprintf("/mod_mu/nodes/%d/info?key=", target)+url.QueryEscape(token), nil)
	if err != nil {
		return "", errors.New("wp2 连接地址请求无效")
	}
	client := *s.client
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("无法读取 wp2 原始连接地址，请连接 wp2 管理员账号")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("wp2 原始配置接口不可用，请连接 wp2 管理员账号")
	}
	var result struct {
		Ret  int `json:"ret"`
		Data struct {
			Server string `json:"server"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result) != nil || result.Ret != 1 || result.Data.Server == "" {
		return "", errors.New("wp2 未返回原始连接地址，请连接管理员账号；不会把 Host/SNI 当作 DNS 目标")
	}
	return wp2ConnectionAddress(result.Data.Server)
}
