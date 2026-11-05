package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
)

func (s *Server) openNetworkConfig(ctx context.Context, account string, payload map[string]any) error {
	b, status, err := s.linodeFor(ctx, account, "GET", "/account/settings", nil)
	if err != nil || status != 200 {
		return errors.New("无法读取 Linode 网络接口设置；默认全端口放行需要 Account Read 权限，或取消勾选后使用账号默认防火墙")
	}
	var settings struct {
		Mode string `json:"interfaces_for_new_linodes"`
	}
	if json.Unmarshal(b, &settings) != nil {
		return errors.New("Linode 网络设置格式无效")
	}
	switch settings.Mode {
	case "linode_only", "linode_default_but_legacy_config_allowed":
		payload["interface_generation"] = "linode"
		payload["interfaces"] = []map[string]any{{"firewall_id": -1, "public": map[string]any{"ipv4": map[string]any{"addresses": []map[string]any{{"address": "auto"}}}}}}
	case "legacy_config_only", "legacy_config_default_but_linode_allowed", "":
		payload["interface_generation"] = "legacy_config"
		payload["firewall_id"] = -1
	default:
		return errors.New("Linode 返回未知接口模式，未创建服务器")
	}
	return nil
}
func (s *Server) openPortsSaved(account string, id int) bool {
	if s.credentials == nil {
		return false
	}
	value, ok := s.credentials.token("open-ports-" + account + "/" + strconv.Itoa(id))
	return ok && value == "true"
}
