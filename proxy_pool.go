package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type poolProxy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Address string `json:"address,omitempty"`
}

func (s *Server) proxyPool() []poolProxy {
	if s.credentials == nil {
		return nil
	}
	raw, _ := s.credentials.token("proxy-pool/0")
	var entries []poolProxy
	_ = json.Unmarshal([]byte(raw), &entries)
	return entries
}
func (s *Server) poolURL(id string) (string, bool) {
	for _, p := range s.proxyPool() {
		if p.ID == id {
			return p.URL, true
		}
	}
	return "", false
}
func (s *Server) proxyPoolAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut {
		fail(w, 405, "Method not allowed")
		return
	}
	if s.credentials == nil {
		fail(w, 503, "代理加密存储未配置")
		return
	}
	if r.Method == "GET" {
		entries := s.proxyPool()
		for i := range entries {
			u, _ := validateProxyURL(entries[i].URL)
			if u != nil {
				entries[i].Address = u.Scheme + "://" + u.Host
			}
			entries[i].URL = ""
		}
		send(w, 200, map[string]any{"proxies": entries})
		return
	}
	var in struct {
		Lines string `json:"lines"`
		ID    string `json:"id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in) != nil {
		fail(w, 400, "请求格式错误")
		return
	}
	if r.Method == "POST" {
		// Serialize pool edits so simultaneous imports cannot overwrite each other.
		s.mu.Lock()
		defer s.mu.Unlock()
		entries := s.proxyPool()
		for lineNo, line := range strings.Split(in.Lines, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 2)
			name := fmt.Sprintf("代理 %d", len(entries)+1)
			raw := parts[0]
			if len(parts) == 2 {
				name = strings.TrimSpace(parts[0])
				raw = strings.TrimSpace(parts[1])
			}
			u, err := validateProxyURL(raw)
			if err != nil {
				fail(w, 400, fmt.Sprintf("第 %d 行代理格式错误，未保存本批次", lineNo+1))
				return
			}
			entries = append(entries, poolProxy{ID: fmt.Sprintf("p-%d-%d", time.Now().UnixNano(), len(entries)), Name: name, URL: u.String()})
		}
		if len(entries) > 500 {
			fail(w, 400, "最多保存 500 个代理")
			return
		}
		data, _ := json.Marshal(entries)
		if err := s.saveRootPassword("proxy-pool", 0, "Proxy pool", string(data)); err != nil {
			fail(w, 500, "代理池保存失败")
			return
		}
		send(w, 200, map[string]bool{"saved": true})
		return
	}
	if r.Method == "PUT" {
		account := r.URL.Query().Get("account_id")
		if _, err := s.accountToken(account); account == "" || err != nil {
			fail(w, 400, "请选择有效账号")
			return
		}
		if in.ID == "" {
			if err := s.credentials.remove("linode-proxy-" + account + "/0"); err != nil {
				fail(w, 500, "解除绑定失败")
				return
			}
			send(w, 200, map[string]bool{"saved": true})
			return
		}
		if _, ok := s.poolURL(in.ID); !ok {
			fail(w, 400, "代理不存在")
			return
		}
		if err := s.saveProxyConfig(account, "pool:"+in.ID); err != nil {
			fail(w, 500, "绑定保存失败")
			return
		}
		send(w, 200, map[string]bool{"saved": true})
		return
	}
}
