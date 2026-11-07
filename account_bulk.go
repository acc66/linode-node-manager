package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type bulkAccountInput struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

// accountBulkAPI imports or removes managed accounts. Import is atomic within
// the account store; deletion reports per-account outcomes because account
// credentials and proxy bindings are stored separately.
func (s *Server) accountBulkAPI(w http.ResponseWriter, r *http.Request) {
	if !s.refillMu.TryRLock() {
		fail(w, 409, "补号或账户运维正在运行，请等待")
		return
	}
	defer s.refillMu.RUnlock()
	if s.accounts == nil {
		fail(w, 503, "请先配置加密存储")
		return
	}
	switch r.Method {
	case http.MethodPost:
		var in struct {
			Accounts []bulkAccountInput `json:"accounts"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
		dec.DisallowUnknownFields()
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || len(in.Accounts) == 0 || len(in.Accounts) > 100 {
			fail(w, 400, "请提交 1-100 个账号，格式为名称和 API Token")
			return
		}
		seen := map[string]bool{}
		for i := range in.Accounts {
			in.Accounts[i].Name = strings.TrimSpace(in.Accounts[i].Name)
			if len(in.Accounts[i].Name) == 0 || len(in.Accounts[i].Name) > 80 || len(in.Accounts[i].Token) < 20 || len(in.Accounts[i].Token) > 512 {
				fail(w, 400, fmt.Sprintf("第 %d 个账号名称或 Token 长度无效，整批未导入", i+1))
				return
			}
			if seen[in.Accounts[i].Name] {
				fail(w, 409, fmt.Sprintf("批次内账号名称重复：%s，整批未导入", in.Accounts[i].Name))
				return
			}
			seen[in.Accounts[i].Name] = true
		}
		store := s.accounts
		store.mu.Lock()
		defer store.mu.Unlock()
		for _, current := range store.accounts {
			if seen[current.Name] {
				fail(w, 409, fmt.Sprintf("账号名称已存在：%s，整批未导入", current.Name))
				return
			}
		}
		created := make([]ManagedAccount, 0, len(in.Accounts))
		for _, item := range in.Accounts {
			idBytes := make([]byte, 16)
			if _, err := rand.Read(idBytes); err != nil {
				fail(w, 500, "生成账号 ID 失败，整批未导入")
				return
			}
			id := hex.EncodeToString(idBytes)
			store.accounts[id] = storedAccount{ID: id, Name: item.Name, Token: item.Token}
			created = append(created, ManagedAccount{ID: id, Name: item.Name})
		}
		if err := store.saveLocked(); err != nil {
			for _, item := range created {
				delete(store.accounts, item.ID)
			}
			fail(w, 500, "账号加密保存失败，整批未导入")
			return
		}
		send(w, 201, map[string]any{"created": created, "count": len(created)})
	case http.MethodDelete:
		var in struct {
			IDs []string `json:"ids"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		dec.DisallowUnknownFields()
		if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || len(in.IDs) == 0 || len(in.IDs) > 100 {
			fail(w, 400, "请选择 1-100 个账号")
			return
		}
		unique := map[string]bool{}
		for _, id := range in.IDs {
			if id == "" || id == "legacy" || unique[id] {
				fail(w, 400, "账号列表无效或包含重复项，未删除")
				return
			}
			unique[id] = true
		}
		tasks, err := s.listRefillTasks()
		if err != nil {
			fail(w, 500, "无法核对补机任务占用，未删除")
			return
		}
		for _, task := range tasks {
			claims := refillClaimedAccounts(task)
			for id := range unique {
				if claims[id] {
					fail(w, 409, fmt.Sprintf("账号 %s 正被补机任务 %s 占用，整批未删除", id, task.Name))
					return
				}
			}
		}
		for id := range unique {
			if _, err := s.accountToken(id); err != nil {
				fail(w, 404, "所选账号中有不存在的账号，整批未删除")
				return
			}
		}
		removed := make([]string, 0, len(unique))
		for id := range unique {
			if err := s.accounts.remove(id); err != nil {
				fail(w, 500, "删除部分账号失败；请刷新账号列表核对")
				return
			}
			removed = append(removed, id)
			if s.credentials != nil {
				if err := s.clearProxyConfig(id); err != nil {
					fail(w, 500, "账号已移除但部分代理解绑失败；请刷新代理池核对")
					return
				}
			}
			s.mu.Lock()
			for key := range s.accountStatus {
				if strings.HasPrefix(key, id+"/") {
					delete(s.accountStatus, key)
				}
			}
			s.mu.Unlock()
		}
		send(w, 200, map[string]any{"deleted": removed, "count": len(removed)})
	default:
		fail(w, 405, "Method not allowed")
	}
}

type bulkProxyBinding struct {
	AccountID string `json:"account_id"`
	ProxyID   string `json:"proxy_id"`
}

func (s *Server) accountBulkBindingsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		fail(w, 405, "Method not allowed")
		return
	}
	if !s.refillMu.TryRLock() {
		fail(w, 409, "补号任务正在运行，不能修改代理绑定")
		return
	}
	defer s.refillMu.RUnlock()
	if s.credentials == nil || s.accounts == nil {
		fail(w, 503, "账号或代理加密存储未配置")
		return
	}
	var in struct {
		Bindings []bulkProxyBinding `json:"bindings"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || len(in.Bindings) == 0 || len(in.Bindings) > 100 {
		fail(w, 400, "请选择 1-100 个账号代理绑定")
		return
	}
	store := s.credentials
	store.mu.Lock()
	defer store.mu.Unlock()
	proxies, err := proxyPoolLocked(store)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	proxyByID := map[string]string{}
	for _, proxy := range proxies {
		proxyByID[proxy.ID] = proxy.URL
	}
	seenAccounts, seenProxies := map[string]bool{}, map[string]bool{}
	endpoints := map[string]string{}
	for _, binding := range in.Bindings {
		if binding.AccountID == "" || binding.AccountID == "legacy" || seenAccounts[binding.AccountID] {
			fail(w, 400, "账号列表无效或重复，未修改绑定")
			return
		}
		if _, err := s.accountToken(binding.AccountID); err != nil {
			fail(w, 400, "所选账号中有不存在的账号，未修改绑定")
			return
		}
		seenAccounts[binding.AccountID] = true
		if binding.ProxyID == "" {
			continue
		}
		raw, ok := proxyByID[binding.ProxyID]
		if !ok {
			fail(w, 400, "所选代理中有不存在的代理，未修改绑定")
			return
		}
		if seenProxies[binding.ProxyID] {
			fail(w, 409, "一个代理不能同时绑定多个账号，未修改绑定")
			return
		}
		seenProxies[binding.ProxyID] = true
		endpoint, endpointErr := proxyEndpointLocked(store, raw)
		if endpointErr != nil {
			fail(w, 400, "代理地址无效，未修改绑定")
			return
		}
		if owner, exists := endpoints[endpoint]; exists && owner != binding.AccountID {
			fail(w, 409, "不同代理记录指向相同端点，未修改绑定")
			return
		}
		endpoints[endpoint] = binding.AccountID
	}
	// Reject endpoint reuse by accounts outside this batch.
	for account, record := range store.accounts {
		if !strings.HasPrefix(account, "linode-proxy-") || !strings.HasSuffix(account, "/0") {
			continue
		}
		owner := strings.TrimSuffix(strings.TrimPrefix(account, "linode-proxy-"), "/0")
		if seenAccounts[owner] {
			continue
		}
		raw, resolveErr := resolveProxyLocked(store, record.Token)
		if resolveErr != nil {
			fail(w, 500, "现有代理绑定损坏，未修改本批次")
			return
		}
		endpoint, endpointErr := proxyEndpointLocked(store, raw)
		if endpointErr == nil {
			if _, collision := endpoints[endpoint]; collision {
				fail(w, 409, "所选代理已绑定批次外的账号，未修改绑定")
				return
			}
		}
	}
	keys := make(map[string]storedAccount, len(in.Bindings)*2)
	for _, binding := range in.Bindings {
		key := "linode-proxy-" + binding.AccountID + "/0"
		enabledKey := "linode-proxy-enabled-" + binding.AccountID + "/0"
		if old, ok := store.accounts[key]; ok {
			keys[key] = old
		} else {
			keys[key] = storedAccount{}
		}
		if old, ok := store.accounts[enabledKey]; ok {
			keys[enabledKey] = old
		} else {
			keys[enabledKey] = storedAccount{}
		}
		if binding.ProxyID == "" {
			delete(store.accounts, key)
			delete(store.accounts, enabledKey)
		} else {
			store.accounts[key] = storedAccount{ID: key, Name: "Linode API proxy", Token: "pool:" + binding.ProxyID}
			store.accounts[enabledKey] = storedAccount{ID: enabledKey, Name: "Proxy enabled", Token: "true"}
		}
	}
	if err := store.saveLocked(); err != nil {
		for key, old := range keys {
			if old.ID == "" {
				delete(store.accounts, key)
			} else {
				store.accounts[key] = old
			}
		}
		fail(w, 500, "代理绑定加密保存失败，原配置已恢复")
		return
	}
	send(w, 200, map[string]int{"saved": len(in.Bindings)})
}
