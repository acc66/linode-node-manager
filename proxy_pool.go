package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type poolProxy struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	URL           string   `json:"url,omitempty"`
	Address       string   `json:"address,omitempty"`
	BoundAccounts []string `json:"bound_accounts,omitempty"`
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

func proxyPoolLocked(store *accountStore) ([]poolProxy, error) {
	var entries []poolProxy
	if record, ok := store.accounts["proxy-pool/0"]; ok {
		if err := json.Unmarshal([]byte(record.Token), &entries); err != nil {
			return nil, errors.New("代理池配置损坏，请恢复凭据文件")
		}
	}
	return entries, nil
}

func saveProxyPoolLocked(store *accountStore, entries []poolProxy) error {
	for i := range entries {
		entries[i].Address = ""
		entries[i].BoundAccounts = nil
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	previous, exists := store.accounts["proxy-pool/0"]
	store.accounts["proxy-pool/0"] = storedAccount{ID: "proxy-pool/0", Name: "Proxy pool", Token: string(data)}
	if err := store.saveLocked(); err != nil {
		if exists {
			store.accounts["proxy-pool/0"] = previous
		} else {
			delete(store.accounts, "proxy-pool/0")
		}
		return err
	}
	return nil
}

func (s *Server) proxyPoolEntryAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		if !s.refillMu.TryRLock() {
			fail(w, 409, "补号任务正在运行，不能修改代理绑定")
			return
		}
		defer s.refillMu.RUnlock()
	}
	if s.credentials == nil {
		fail(w, 503, "代理加密存储未配置")
		return
	}
	var input struct {
		Name *string `json:"name"`
		URL  string  `json:"url"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || (input.Name == nil && strings.TrimSpace(input.URL) == "") {
		fail(w, 400, "请提交代理名称或完整新地址")
		return
	}
	if input.Name != nil {
		*input.Name = strings.TrimSpace(*input.Name)
		if len(*input.Name) == 0 || utf8.RuneCountInString(*input.Name) > 80 {
			fail(w, 400, "代理名称不能为空且不能超过 80 个字符")
			return
		}
	}
	input.URL = strings.TrimSpace(input.URL)
	if input.URL != "" {
		u, err := validateProxyURL(input.URL)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		input.URL = u.String()
	}
	store := s.credentials
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := proxyPoolLocked(store)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	index := -1
	for i := range entries {
		if entries[i].ID == r.PathValue("id") {
			index = i
			break
		}
	}
	if index < 0 {
		fail(w, 404, "代理不存在，请刷新代理池")
		return
	}
	if input.Name != nil {
		entries[index].Name = *input.Name
	}
	if input.URL != "" {
		entries[index].URL = input.URL
		// Temporarily resolve bindings against the candidate pool while holding
		// the same lock used by account binding; restore before committing.
		previous := store.accounts["proxy-pool/0"]
		candidate, _ := json.Marshal(entries)
		store.accounts["proxy-pool/0"] = storedAccount{ID: "proxy-pool/0", Token: string(candidate)}
		owners, checkErr := proxyOwnersLocked(store, input.URL)
		store.accounts["proxy-pool/0"] = previous
		if checkErr != nil || len(owners) > 1 {
			fail(w, 409, "新代理地址与其他账号的绑定冲突，原资料保留")
			return
		}
	}
	if err := saveProxyPoolLocked(store, entries); err != nil {
		fail(w, 500, "代理资料保存失败，原资料保留")
		return
	}
	send(w, 200, map[string]bool{"saved": true})
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
	if r.Method != "GET" {
		if !s.refillMu.TryRLock() {
			fail(w, 409, "补号任务正在运行，不能修改代理绑定")
			return
		}
		defer s.refillMu.RUnlock()
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut {
		fail(w, 405, "Method not allowed")
		return
	}
	if s.credentials == nil {
		fail(w, 503, "代理加密存储未配置")
		return
	}
	if r.Method == "GET" {
		s.credentials.mu.RLock()
		entries, err := proxyPoolLocked(s.credentials)
		if err != nil {
			s.credentials.mu.RUnlock()
			fail(w, 500, err.Error())
			return
		}
		owners := proxyOwnershipLocked(s.credentials)
		for i := range entries {
			endpoint, _ := proxyEndpointLocked(s.credentials, entries[i].URL)
			entries[i].BoundAccounts = owners[endpoint]
			sort.Strings(entries[i].BoundAccounts)
			u, _ := validateProxyURL(entries[i].URL)
			if u != nil {
				entries[i].Address = u.Scheme + "://" + u.Host
			}
			entries[i].URL = ""
		}
		s.credentials.mu.RUnlock()
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
		// Imports, edits and bindings share one transaction lock.
		s.credentials.mu.Lock()
		defer s.credentials.mu.Unlock()
		entries, err := proxyPoolLocked(s.credentials)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
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
		if err := saveProxyPoolLocked(s.credentials, entries); err != nil {
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
			if err := s.clearProxyConfig(account); err != nil {
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
			if errors.Is(err, errProxyAlreadyBound) {
				fail(w, 409, err.Error())
				return
			}
			fail(w, 500, "绑定保存失败")
			return
		}
		send(w, 200, map[string]bool{"saved": true})
		return
	}
}
