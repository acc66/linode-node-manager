package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type DNSConfig struct {
	Zone            string `json:"zone"`
	Provider        string `json:"provider"`
	Token           string `json:"token,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	Enabled         bool   `json:"enabled"`
}

func normalizeZone(raw string) (string, error) {
	zone := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(zone) > 253 || !strings.Contains(zone, ".") || net.ParseIP(zone) != nil {
		return "", errors.New("请输入 DNS 托管域名，例如 example.com，不要填写网址或 IP")
	}
	for _, label := range strings.Split(zone, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("域名格式无效")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("域名仅支持 ASCII，请将国际化域名转换为 Punycode")
			}
		}
	}
	return zone, nil
}
func (s *Server) dnsConfigs() ([]DNSConfig, error) {
	configs := []DNSConfig{}
	if s.credentials == nil {
		return configs, nil
	}
	s.credentials.mu.RLock()
	defer s.credentials.mu.RUnlock()
	for id, value := range s.credentials.accounts {
		if !strings.HasPrefix(id, "dns-provider-") {
			continue
		}
		var config DNSConfig
		if json.Unmarshal([]byte(value.Token), &config) != nil {
			return nil, errors.New("DNS 配置损坏，请重新保存")
		}
		configs = append(configs, config)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Zone < configs[j].Zone })
	return configs, nil
}
func (s *Server) dnsConfigFor(domain string) (*DNSConfig, error) {
	configs, err := s.dnsConfigs()
	if err != nil {
		return nil, err
	}
	var chosen *DNSConfig
	for _, config := range configs {
		if (domain == config.Zone || strings.HasSuffix(domain, "."+config.Zone)) && (chosen == nil || len(config.Zone) > len(chosen.Zone)) {
			copy := config
			chosen = &copy
		}
	}
	if chosen != nil && !chosen.Enabled {
		return nil, nil
	}
	return chosen, nil
}
func (s *Server) dnsProvidersAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		configs, err := s.dnsConfigs()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		safe := []map[string]any{}
		for _, config := range configs {
			safe = append(safe, map[string]any{"zone": config.Zone, "provider": config.Provider, "enabled": config.Enabled, "configured": true})
		}
		send(w, 200, map[string]any{"providers": safe})
		return
	case "POST":
		var config DNSConfig
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&config) != nil {
			fail(w, 400, "Invalid DNS configuration")
			return
		}
		zone, err := normalizeZone(config.Zone)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		config.Zone = zone
		config.Token = strings.TrimSpace(config.Token)
		config.AccessKeyID = strings.TrimSpace(config.AccessKeyID)
		config.AccessKeySecret = strings.TrimSpace(config.AccessKeySecret)
		switch config.Provider {
		case "cloudflare":
			if strings.TrimSpace(config.Token) == "" {
				fail(w, 400, "请填写 Cloudflare API Token")
				return
			}
			config.AccessKeyID = ""
			config.AccessKeySecret = ""
		case "alidns":
			if strings.TrimSpace(config.AccessKeyID) == "" || strings.TrimSpace(config.AccessKeySecret) == "" {
				fail(w, 400, "请填写阿里云 AccessKey ID 和 Secret")
				return
			}
			config.Token = ""
		default:
			fail(w, 400, "请选择 Cloudflare 或阿里云 DNS")
			return
		}
		raw, _ := json.Marshal(config)
		if err := s.saveRootPassword("dns-provider-"+zone, 0, "DNS "+zone, string(raw)); err != nil {
			fail(w, 500, "无法加密保存 DNS Key，请检查 ACCOUNT_ENCRYPTION_KEY")
			return
		}
		send(w, 200, map[string]bool{"saved": true})
		return
	case "PATCH":
		zone, err := normalizeZone(r.URL.Query().Get("zone"))
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil || input.Enabled == nil {
			fail(w, 400, "请指定 enabled")
			return
		}
		configs, err := s.dnsConfigs()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		for _, config := range configs {
			if config.Zone != zone {
				continue
			}
			config.Enabled = *input.Enabled
			raw, _ := json.Marshal(config)
			if err := s.saveRootPassword("dns-provider-"+zone, 0, "DNS "+zone, string(raw)); err != nil {
				fail(w, 500, "无法保存 DNS 状态")
				return
			}
			send(w, 200, map[string]bool{"saved": true})
			return
		}
		fail(w, 404, "DNS 配置不存在")
		return

	case "DELETE":
		zone, err := normalizeZone(r.URL.Query().Get("zone"))
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if s.credentials != nil {
			err = s.credentials.remove("dns-provider-" + zone + "/0")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				fail(w, 500, "无法删除 DNS 配置")
				return
			}
		}
		send(w, 200, map[string]bool{"deleted": true})
		return
	default:
		fail(w, 405, "Method not allowed")
	}
}
func (s *Server) dnsCheckAPI(w http.ResponseWriter, r *http.Request) {
	zone, err := normalizeZone(r.URL.Query().Get("zone"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	configs, err := s.dnsConfigs()
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	for _, config := range configs {
		if config.Zone != zone {
			continue
		}
		if config.Provider == "cloudflare" {
			_, err = s.cfZone(r.Context(), config)
		} else {
			var result map[string]any
			err = s.aliRequest(r.Context(), config, "DescribeDomainInfo", url.Values{"DomainName": {zone}}, &result)
		}
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		send(w, 200, map[string]string{"status": "ok", "message": "域名读取权限验证成功；写入权限将在安装更新记录时验证"})
		return
	}
	fail(w, 404, "未找到该域名的 DNS 配置")
}
func (s *Server) dnsHTTP(ctx context.Context, method, target string, headers map[string]string, body io.Reader, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return errors.New("DNS 请求参数无效")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := *s.client
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("DNS 服务连接失败，请检查管理机出站网络")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Keep upstream error details (especially AliDNS's machine-readable Code)
		// so a bad parameter can be distinguished from an expired key. Never echo
		// the request URL/body, which may contain credentials or signatures.
		var detail struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
			Error   string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&detail)
		code := detail.Code
		if code == "" {
			code = detail.Error
		}
		code = safeDNSError(code, 100)
		message := safeDNSError(detail.Message, 180)
		if code != "" && message != "" {
			return fmt.Errorf("DNS API HTTP %d (%s): %s", resp.StatusCode, code, message)
		}
		if code != "" {
			return fmt.Errorf("DNS API HTTP %d (%s)", resp.StatusCode, code)
		}
		return fmt.Errorf("DNS API HTTP %d，请检查域名、请求参数与 Key 权限", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(result); err != nil {
		return errors.New("DNS API 响应格式无效")
	}
	return nil
}

func safeDNSError(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, value)
	// Do not let a provider echo an access key, token, or request signature into
	// the dashboard/job log.
	for _, marker := range []string{"AccessKeySecret", "AccessKeyId", "Signature", "Token", "Secret"} {
		for start := 0; ; {
			i := strings.Index(strings.ToLower(value[start:]), strings.ToLower(marker))
			if i < 0 {
				break
			}
			i += start
			end := strings.IndexAny(value[i:], " ,;\"'&")
			if end < 0 {
				end = len(value) - i
			}
			value = value[:i] + marker + "=[redacted]" + value[i+end:]
			start = i + len(marker) + len("=[redacted]")
			if start >= len(value) {
				break
			}
		}
	}
	value = strings.TrimSpace(value)
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
func (s *Server) cfRequest(ctx context.Context, config DNSConfig, method, path string, payload any, result any) error {
	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = bytes.NewReader(data)
	}
	var envelope struct {
		Success    bool            `json:"success"`
		Result     json.RawMessage `json:"result"`
		ResultInfo struct {
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	err := s.dnsHTTP(ctx, method, strings.TrimRight(env("DNS_CF_API_BASE_URL", "https://api.cloudflare.com/client/v4"), "/")+path, map[string]string{"Authorization": "Bearer " + config.Token, "Content-Type": "application/json"}, body, &envelope)
	if err != nil {
		return err
	}
	if !envelope.Success {
		return errors.New("Cloudflare 拒绝 DNS 请求，请检查 Zone Read / DNS Edit 权限")
	}
	if result != nil {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return errors.New("Cloudflare DNS 返回格式无效")
		}
	}
	return nil
}
func (s *Server) cfZone(ctx context.Context, config DNSConfig) (string, error) {
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	err := s.cfRequest(ctx, config, "GET", "/zones?name="+url.QueryEscape(config.Zone)+"&status=active", nil, &zones)
	if err != nil {
		return "", err
	}
	if len(zones) != 1 || zones[0].Name != config.Zone || zones[0].ID == "" {
		return "", errors.New("Cloudflare 未找到唯一的已激活托管域名，请检查域名、Token 和 NS 托管状态")
	}
	return zones[0].ID, nil
}
func percentEncode(raw string) string { return strings.ReplaceAll(url.QueryEscape(raw), "+", "%20") }
func signAli(values url.Values, secret string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, percentEncode(key)+"="+percentEncode(values.Get(key)))
	}
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte("POST&%2F&" + percentEncode(strings.Join(pairs, "&"))))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func (s *Server) aliRequest(ctx context.Context, config DNSConfig, action string, params url.Values, result any) error {
	values := url.Values{}
	for key, items := range params {
		values[key] = items
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return errors.New("DNS 请求随机数生成失败")
	}
	for key, value := range map[string]string{"Action": action, "Version": "2015-01-09", "Format": "JSON", "AccessKeyId": config.AccessKeyID, "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": hex.EncodeToString(nonce), "Timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z")} {
		values.Set(key, value)
	}
	values.Set("Signature", signAli(values, config.AccessKeySecret))
	var raw json.RawMessage
	err := s.dnsHTTP(ctx, "POST", env("DNS_ALI_API_BASE_URL", "https://alidns.aliyuncs.com/"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, strings.NewReader(values.Encode()), &raw)
	if err != nil {
		return err
	}
	var status struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if json.Unmarshal(raw, &status) != nil {
		return errors.New("阿里云 DNS 响应格式无效")
	}
	if status.Code != "" {
		code := safeDNSError(status.Code, 100)
		message := safeDNSError(status.Message, 180)
		if message != "" {
			return fmt.Errorf("阿里云 DNS 拒绝请求 (%s): %s", code, message)
		}
		return fmt.Errorf("阿里云 DNS 拒绝请求 (%s)，请检查域名和 RAM DNS 读写权限", code)
	}
	if result != nil {
		if json.Unmarshal(raw, result) != nil {
			return errors.New("阿里云 DNS 返回格式无效")
		}
	}
	return nil
}
