package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func (s *Server) wp2NodeDomain(ctx context.Context, base, token string, target int) (string, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+fmt.Sprintf("/api/v1/server/UniProxy/config?node_id=%d", target), nil)
	if err != nil {
		return "", errors.New("wp2 节点配置地址无效")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := *s.client
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(request)
	if err != nil {
		return "", errors.New("无法读取 wp2 节点域名")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("读取 wp2 节点配置 HTTP %d", resp.StatusCode)
	}
	var config struct {
		Domain      string `json:"domain"`
		ServerName  string `json:"server_name"`
		TLSSettings struct {
			ServerName string `json:"server_name"`
		} `json:"tls_settings"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&config) != nil {
		return "", errors.New("wp2 节点配置格式无效")
	}
	domain := config.TLSSettings.ServerName
	if domain == "" {
		domain = config.ServerName
	}
	if domain == "" {
		domain = config.Domain
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")), nil
}
func (s *Server) discoverDNSZones(ctx context.Context, config DNSConfig) ([]string, error) {
	zones := []string{}
	complete := false
	switch config.Provider {
	case "cloudflare":
		if strings.TrimSpace(config.Token) == "" {
			return nil, errors.New("请先填写 Cloudflare API Token")
		}
		for page := 1; page <= 200; page++ {
			var batch []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			}
			if err := s.cfRequest(ctx, config, "GET", fmt.Sprintf("/zones?status=active&per_page=50&page=%d", page), nil, &batch); err != nil {
				return nil, err
			}
			for _, zone := range batch {
				if name, err := normalizeZone(zone.Name); err == nil {
					zones = append(zones, name)
				}
			}
			if len(batch) < 50 {
				complete = true
				break
			}
		}
	case "alidns":
		if strings.TrimSpace(config.AccessKeyID) == "" || strings.TrimSpace(config.AccessKeySecret) == "" {
			return nil, errors.New("请先填写阿里云 AccessKey ID 和 Secret")
		}
		for page := 1; page <= 100; page++ {
			var result struct {
				TotalCount int `json:"TotalCount"`
				Domains    struct {
					Domain []struct {
						Name string `json:"DomainName"`
					} `json:"Domain"`
				} `json:"Domains"`
			}
			if err := s.aliRequest(ctx, config, "DescribeDomains", url.Values{"PageNumber": {strconv.Itoa(page)}, "PageSize": {"100"}}, &result); err != nil {
				return nil, err
			}
			for _, zone := range result.Domains.Domain {
				if name, err := normalizeZone(zone.Name); err == nil {
					zones = append(zones, name)
				}
			}
			if page*100 >= result.TotalCount {
				complete = true
				break
			}
			if len(result.Domains.Domain) == 0 {
				return nil, errors.New("阿里云域名列表不完整")
			}
		}
	default:
		return nil, errors.New("请选择 Cloudflare 或阿里云 DNS")
	}
	if !complete {
		return nil, errors.New("域名数量超过读取上限，请手动填写托管域名")
	}
	sort.Strings(zones)
	unique := zones[:0]
	for _, zone := range zones {
		if len(unique) == 0 || unique[len(unique)-1] != zone {
			unique = append(unique, zone)
		}
	}
	return unique, nil
}
func (s *Server) dnsDiscoverAPI(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DNSConfig
		NodeID int `json:"node_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in) != nil {
		fail(w, 400, "DNS 参数无效")
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	in.AccessKeyID = strings.TrimSpace(in.AccessKeyID)
	in.AccessKeySecret = strings.TrimSpace(in.AccessKeySecret)
	zones, err := s.discoverDNSZones(r.Context(), in.DNSConfig)
	if err != nil {
		fail(w, 502, err.Error()+"；需要域名列表读取权限，也可手动填写托管域名")
		return
	}
	domain := ""
	message := ""
	suggested := ""
	if in.NodeID > 0 {
		u, err := wp2Base()
		if err == nil {
			domain, err = s.wp2NodeDomain(r.Context(), u.String(), env("WP2_API_TOKEN", ""), in.NodeID)
			if err != nil {
				message = "已读取托管域名，但未能读取所选 wp2 节点域名，请手动选择。"
			}
		}
	}
	for _, zone := range zones {
		if (domain == zone || strings.HasSuffix(domain, "."+zone)) && len(zone) > len(suggested) {
			suggested = zone
		}
	}
	if suggested == "" && domain == "" && len(zones) == 1 {
		suggested = zones[0]
	}
	if domain != "" && suggested == "" {
		message = "所选节点域名 " + domain + " 不属于当前 Key 可管理的托管域名，请检查对应 DNS 账号或 wp2 节点域名。"
	}
	send(w, 200, map[string]any{"zones": zones, "suggested_zone": suggested, "node_domain": domain, "message": message})
}
