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
	"time"
)

const ipTraceProbeID = "iptrace-probe/0"

func (s *Server) ipTraceProbeKey() (string, bool) {
	if s.credentials == nil {
		return "", false
	}
	return s.credentials.token(ipTraceProbeID)
}

func (s *Server) ipTraceRequest(ctx context.Context, path string) ([]byte, int, error) {
	key, ok := s.ipTraceProbeKey()
	if !ok || key == "" {
		return nil, 0, errors.New("尚未保存 IPTrace API Key")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://iptrace.net"+path, nil)
	if err != nil {
		return nil, 0, errors.New("IPTrace 请求参数无效")
	}
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Accept", "application/json")
	client := *s.client
	client.Timeout = 20 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("IPTrace 网络连接失败")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, response.StatusCode, errors.New("IPTrace 响应读取失败")
	}
	return body, response.StatusCode, nil
}

func (s *Server) verifyIPTraceKey(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 512 {
		return errors.New("请填写有效的 IPTrace API Key")
	}
	if s.credentials == nil {
		return errors.New("加密凭据存储未启用")
	}
	oldKey, hadOld := s.ipTraceProbeKey()
	// Validate without triggering a billable TCP probe.
	if err := s.saveRootPassword("iptrace-probe", 0, "IPTrace probe", key); err != nil {
		return errors.New("IPTrace Key 加密保存失败")
	}
	restore := func() {
		if hadOld {
			_ = s.saveRootPassword("iptrace-probe", 0, "IPTrace probe", oldKey)
		} else {
			_ = s.credentials.remove(ipTraceProbeID)
		}
	}
	body, status, err := s.ipTraceRequest(ctx, "/api/user/me")
	if err != nil {
		restore()
		return err
	}
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Code != 0 {
		restore()
		return errors.New("IPTrace Key 验证失败，请检查 Key 和账户状态")
	}
	return nil
}

func (s *Server) ipTraceProbeSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_, configured := s.ipTraceProbeKey()
		provider, _ := s.chinaProbeProvider()
		send(w, 200, map[string]any{"configured": configured, "selected": provider == "iptrace", "selected_provider": provider})
	case http.MethodPost:
		var in struct {
			Key string `json:"key"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in) != nil {
			fail(w, 400, "IPTrace 配置格式无效")
			return
		}
		if strings.TrimSpace(in.Key) == "" {
			if old, ok := s.ipTraceProbeKey(); ok {
				in.Key = old
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		if err := s.verifyIPTraceKey(ctx, in.Key); err != nil {
			fail(w, 502, err.Error())
			return
		}
		if err := s.setChinaProbeProvider("iptrace"); err != nil {
			fail(w, 500, "IPTrace 已验证，但选择探测方式失败")
			return
		}
		send(w, 200, map[string]any{"saved": true, "provider": "iptrace"})
	case http.MethodDelete:
		if s.credentials == nil {
			fail(w, 503, "加密凭据存储未启用")
			return
		}
		if _, ok := s.credentials.token(ipTraceProbeID); ok {
			if err := s.credentials.remove(ipTraceProbeID); err != nil {
				fail(w, 500, "无法移除 IPTrace Key")
				return
			}
		}
		if s.chinaProbeConfigured("aliyun") {
			_ = s.setChinaProbeProvider("aliyun")
		}
		send(w, 200, map[string]bool{"deleted": true})
	default:
		fail(w, 405, "Method not allowed")
	}
}

func (s *Server) checkIPTraceTCP(ctx context.Context, targetIP string, port int) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil || ip.To4() == nil || port < 1 || port > 65535 {
		return "", errors.New("待测 IP 或 TCP 端口无效")
	}
	target := url.PathEscape(fmt.Sprintf("%s:%d", ip.To4().String(), port))
	body, status, err := s.ipTraceRequest(ctx, "/api/tcping/"+target+"?count=1&country=CN")
	if err != nil {
		return "", err
	}
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Recv   int     `json:"recv"`
			Sent   int     `json:"sent"`
			Loss   float64 `json:"loss"`
			Source struct {
				Type        string `json:"type"`
				CountryCode string `json:"country_code"`
				Name        string `json:"name"`
				City        string `json:"city"`
			} `json:"source"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil {
		return "", errors.New("IPTrace 返回的 TCP 检测数据格式无效")
	}
	if result.Code != 0 || status != http.StatusOK {
		return "", errors.New("IPTrace 中国节点检测失败；请检查 Key、点数或中国节点状态")
	}
	if result.Data.Source.Type != "node" || result.Data.Source.CountryCode != "CN" {
		return "", errors.New("IPTrace 未确认使用中国节点，本次检测不作为换 IP 依据")
	}
	output := fmt.Sprintf("IPTrace 中国节点 %s %s：接收 %d/%d，丢包 %.0f%%", result.Data.Source.Name, result.Data.Source.City, result.Data.Recv, result.Data.Sent, result.Data.Loss)
	if result.Data.Recv > 0 && result.Data.Loss < 100 {
		return output, nil
	}
	return output, fmt.Errorf("%w：IPTrace 中国节点无法连接 %s:%d", errDomesticTCPUnreachable, ip.To4().String(), port)
}
