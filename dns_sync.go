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
	"strings"
)

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}
type aliRecord struct {
	ID     string `json:"RecordId"`
	Type   string `json:"Type"`
	RR     string `json:"RR"`
	Value  string `json:"Value"`
	Line   string `json:"Line"`
	Status string `json:"Status"`
}

func (s *Server) syncCloudflare(ctx context.Context, config DNSConfig, domain, ipv4, ipv6 string) error {
	zone, err := s.cfZone(ctx, config)
	if err != nil {
		return err
	}
	prefix := "/zones/" + url.PathEscape(zone) + "/dns_records"
	records := []cfRecord{}
	complete := false
	for page := 1; page <= 100; page++ {
		var batch []cfRecord
		err = s.cfRequest(ctx, config, "GET", prefix+"?name="+url.QueryEscape(domain)+fmt.Sprintf("&per_page=100&page=%d", page), nil, &batch)
		if err != nil {
			return err
		}
		for _, record := range batch {
			if strings.EqualFold(strings.TrimSuffix(record.Name, "."), domain) {
				records = append(records, record)
			}
		}
		if len(batch) < 100 {
			complete = true
			break
		}
	}
	if !complete {
		return errors.New("Cloudflare 节点记录超过分页上限，未修改 DNS")
	}
	for _, record := range records {
		if record.Type == "CNAME" {
			return errors.New("节点域名存在 CNAME，请先确认并移除冲突记录；未自动删除 CNAME")
		}
	}
	for _, kind := range []string{"A", "AAAA"} {
		value := ipv4
		if kind == "AAAA" {
			value = ipv6
		}
		found := false
		for _, record := range records {
			if record.Type != kind {
				continue
			}
			found = true
			path := prefix + "/" + url.PathEscape(record.ID)
			if value == "" {
				if err := s.cfRequest(ctx, config, "DELETE", path, nil, nil); err != nil {
					return err
				}
				continue
			}
			payload := map[string]any{"type": kind, "name": domain, "content": value, "ttl": 60, "proxied": false}
			if err := s.cfRequest(ctx, config, "PATCH", path, payload, nil); err != nil {
				return err
			}
		}
		if !found && value != "" {
			if err := s.cfRequest(ctx, config, "POST", prefix, map[string]any{"type": kind, "name": domain, "content": value, "ttl": 60, "proxied": false}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Server) syncAliDNS(ctx context.Context, config DNSConfig, domain, ipv4, ipv6 string) error {
	rr := strings.TrimSuffix(domain, "."+config.Zone)
	if domain == config.Zone {
		rr = "@"
	}
	records := []aliRecord{}
	complete := false
	for page := 1; page <= 100; page++ {
		var result struct {
			TotalCount    int `json:"TotalCount"`
			DomainRecords struct {
				Record []aliRecord `json:"Record"`
			} `json:"DomainRecords"`
		}
		err := s.aliRequest(ctx, config, "DescribeDomainRecords", url.Values{"DomainName": {config.Zone}, "RRKeyWord": {rr}, "PageSize": {"100"}, "PageNumber": {fmt.Sprint(page)}}, &result)
		if err != nil {
			return err
		}
		for _, record := range result.DomainRecords.Record {
			if strings.EqualFold(record.RR, rr) {
				records = append(records, record)
			}
		}
		if page*100 >= result.TotalCount {
			complete = true
			break
		}
		if len(result.DomainRecords.Record) == 0 {
			return errors.New("阿里云 DNS 分页数据不完整，未修改 DNS")
		}
	}
	if !complete {
		return errors.New("阿里云节点记录超过分页上限，未修改 DNS")
	}
	for _, record := range records {
		if record.Type == "CNAME" {
			return errors.New("节点域名存在 CNAME，请先确认并移除冲突记录；未自动删除 CNAME")
		}
	}
	for _, kind := range []string{"A", "AAAA"} {
		value := ipv4
		if kind == "AAAA" {
			value = ipv6
		}
		found := false
		for _, record := range records {
			if record.Type != kind {
				continue
			}
			found = true
			if value == "" {
				if err := s.aliRequest(ctx, config, "DeleteDomainRecord", url.Values{"RecordId": {record.ID}}, nil); err != nil {
					return err
				}
				continue
			}
			params := url.Values{"RecordId": {record.ID}, "RR": {rr}, "Type": {kind}, "Value": {value}, "TTL": {"600"}}
			if record.Line != "" {
				params.Set("Line", record.Line)
			}
			if err := s.aliRequest(ctx, config, "UpdateDomainRecord", params, nil); err != nil {
				return err
			}
			if record.Status != "" && record.Status != "ENABLE" {
				if err := s.aliRequest(ctx, config, "SetDomainRecordStatus", url.Values{"RecordId": {record.ID}, "Status": {"Enable"}}, nil); err != nil {
					return err
				}
			}
		}
		if !found && value != "" {
			if err := s.aliRequest(ctx, config, "AddDomainRecord", url.Values{"DomainName": {config.Zone}, "RR": {rr}, "Type": {kind}, "Value": {value}, "TTL": {"600"}}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Server) prepareDeploymentDNS(ctx context.Context, base, token string, target int, instance Instance) (bool, string, error) {
	configs, err := s.dnsConfigs()
	if err != nil {
		return false, "", err
	}
	active := false
	for _, config := range configs {
		if config.Enabled {
			active = true
		}
	}
	if !active {
		return false, "", nil
	}
	request, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+fmt.Sprintf("/api/v1/server/UniProxy/config?node_id=%d", target), nil)
	if err != nil {
		return false, "", errors.New("wp2 节点配置地址无效")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := *s.client
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(request)
	if err != nil {
		return false, "", errors.New("自动 DNS 无法读取 wp2 节点配置")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, "", fmt.Errorf("自动 DNS 读取 wp2 配置 HTTP %d", resp.StatusCode)
	}
	var config struct {
		Domain      string `json:"domain"`
		ServerName  string `json:"server_name"`
		TLSSettings struct {
			ServerName string `json:"server_name"`
		} `json:"tls_settings"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&config) != nil {
		return false, "", errors.New("wp2 节点配置格式无效")
	}
	domain := config.TLSSettings.ServerName
	if domain == "" {
		domain = config.ServerName
	}
	if domain == "" {
		domain = config.Domain
	}
	if domain == "" || net.ParseIP(domain) != nil {
		return false, "未识别到可自动解析的节点域名，交由节点安装检查。\n", nil
	}
	domain, err = normalizeZone(domain)
	if err != nil {
		return false, "", err
	}
	provider, err := s.dnsConfigFor(domain)
	if err != nil {
		return false, "", err
	}
	if provider == nil {
		return false, "节点域名没有匹配的已启用 DNS 配置，将检查现有解析。\n", nil
	}
	panelURL, _ := url.Parse(base)
	if domain == provider.Zone || domain == strings.ToLower(panelURL.Hostname()) || domain == strings.ToLower(env("PANEL_DOMAIN", "")) {
		return false, "", errors.New("自动 DNS 不修改根域名、wp2 地址或管理面板域名；请为节点配置独立子域名")
	}
	ipv4 := publicIP(instance)
	ipv6 := strings.Split(instance.IPv6, "/")[0]
	if ipv6 != "" {
		parsed := net.ParseIP(ipv6)
		if parsed == nil || parsed.To4() != nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
			return false, "", errors.New("实例 IPv6 格式无效，未修改 DNS")
		}
	}
	if provider.Provider == "cloudflare" {
		err = s.syncCloudflare(ctx, *provider, domain, ipv4, ipv6)
	} else if provider.Provider == "alidns" {
		err = s.syncAliDNS(ctx, *provider, domain, ipv4, ipv6)
	} else {
		err = errors.New("不支持的 DNS 服务商")
	}
	if err != nil {
		return false, "", fmt.Errorf("自动 DNS 未完成，记录可能已部分更新：%w", err)
	}
	return true, fmt.Sprintf("自动 DNS 已更新 %s（%s），A/AAAA 指向所选实例，等待解析生效。\n", domain, provider.Provider), nil
}
