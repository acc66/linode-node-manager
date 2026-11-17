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

type isolationContextKey struct{}
type EgressRecord struct {
	IP    string `json:"ip"`
	Proxy string `json:"proxy"`
	First string `json:"first_seen"`
	Last  string `json:"last_seen"`
	Uses  int    `json:"uses"`
}
type AccountEgress struct {
	Account string         `json:"account_id"`
	Records []EgressRecord `json:"records"`
}
type egressConflict struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	Proxy       string `json:"proxy"`
}

func (s *Server) isolationEnabled() bool {
	if s.credentials == nil {
		return false
	}
	value, _ := s.credentials.token("account-isolation/0")
	return value == "true"
}

// The IP lookup never receives a Linode token or browser credentials.
func (s *Server) lookupEgress(ctx context.Context, raw string) (string, error) {
	if s.egressLookup != nil {
		return s.egressLookup(ctx, raw)
	}
	return s.lookupEgressEndpoint(ctx, raw, env("EGRESS_CHECK_URL", "https://api4.ipify.org?format=json"))
}

func (s *Server) lookupEgressIPv6(ctx context.Context, raw string) (string, error) {
	if s.egressLookupIPv6 != nil {
		return s.egressLookupIPv6(ctx, raw)
	}
	if s.egressLookup != nil {
		return "", errors.New("IPv6 检测未配置")
	}
	return s.lookupEgressEndpoint(ctx, raw, env("EGRESS_CHECK_URL_IPV6", "https://api6.ipify.org?format=json"))
}

func (s *Server) lookupEgressEndpoint(ctx context.Context, raw, endpoint string) (string, error) {
	client, err := proxyClient(s.client, raw)
	if err != nil {
		return "", err
	}
	defer client.CloseIdleConnections()
	client.Timeout = 12 * time.Second
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("出口检测地址必须是 HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", errors.New("出口检测地址无效")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("代理出口检测失败；未切换直连")
	}
	defer resp.Body.Close()
	var data struct {
		IP string `json:"ip"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 2048)).Decode(&data) != nil {
		return "", errors.New("出口检测响应无效")
	}
	ip := net.ParseIP(strings.TrimSpace(data.IP))
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", errors.New("出口检测未返回公网 IP")
	}
	if strings.Contains(u.Hostname(), "api6.") && ip.To4() != nil {
		return "", errors.New("代理没有可用的 IPv6 出口")
	}
	return ip.String(), nil
}

func (s *Server) verifyAccountEgress(ctx context.Context, account string) (string, error) {
	if account == "" {
		account = "legacy"
	}
	raw, err := s.proxyForRequest(account)
	if err != nil {
		return "", fmt.Errorf("账号必须绑定独占代理：%w", err)
	}
	ip, err := s.lookupEgress(ctx, raw)
	if err != nil {
		return "", err
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || parsed.To4() == nil {
		return "", errors.New("代理出口 IP 无效")
	}
	ip = parsed.String()
	accountNames := map[string]string{"legacy": "默认账号 (.env)"}
	if s.accounts != nil {
		for _, managed := range s.accounts.list() {
			accountNames[managed.ID] = managed.Name
		}
	}
	store := s.credentials
	store.mu.Lock()
	defer store.mu.Unlock()
	// Recheck the binding after the external lookup to avoid recording a stale proxy.
	binding, ok := store.accounts["linode-proxy-"+account+"/0"]
	current, resolveErr := resolveProxyLocked(store, binding.Token)
	if !ok || resolveErr != nil || current != raw {
		return "", errors.New("检测期间代理绑定发生变化，请重试")
	}
	endpoint, err := proxyEndpointLocked(store, raw)
	if err != nil {
		return "", err
	}
	var own AccountEgress
	key := "account-egress-" + account + "/0"
	for id, record := range store.accounts {
		if !strings.HasPrefix(id, "account-egress-") {
			continue
		}
		var prior AccountEgress
		if json.Unmarshal([]byte(record.Token), &prior) != nil {
			return "", errors.New("账号出口记录损坏，已阻止请求")
		}
		if id == key {
			own = prior
			continue
		}
		for _, seen := range prior.Records {
			if seen.IP == ip {
				name := accountNames[prior.Account]
				if name == "" {
					name = prior.Account
				}
				return "", fmt.Errorf("出口 IP %s 已由账号「%s」经代理 %s 使用；当前代理 %s 也出口到此 IP，已阻止 Linode 请求。请更换独立公网出口（只改端口无效）", ip, name, seen.Proxy, endpoint)
			}
		}
	}
	own.Account = account
	now := time.Now().UTC().Format(time.RFC3339)
	found := false
	for i := range own.Records {
		if own.Records[i].IP == ip && own.Records[i].Proxy == endpoint {
			own.Records[i].Last = now
			own.Records[i].Uses++
			found = true
			break
		}
	}
	if !found {
		if len(own.Records) >= 1000 {
			return "", errors.New("账号出口历史已达上限，请先人工归档")
		}
		own.Records = append(own.Records, EgressRecord{IP: ip, Proxy: endpoint, First: now, Last: now, Uses: 1})
	}
	data, _ := json.Marshal(own)
	previous, existed := store.accounts[key]
	store.accounts[key] = storedAccount{ID: key, Name: "Account egress history", Token: string(data)}
	if err := store.saveLocked(); err != nil {
		if existed {
			store.accounts[key] = previous
		} else {
			delete(store.accounts, key)
		}
		return "", errors.New("出口记录保存失败，已阻止请求")
	}
	return ip, nil
}

func (s *Server) accountPoolAPI(w http.ResponseWriter, r *http.Request) {
	if s.credentials == nil {
		fail(w, 503, "请先配置加密存储")
		return
	}
	if r.Method == "PUT" {
		var in struct {
			Strict bool `json:"strict"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in) != nil {
			fail(w, 400, "配置格式无效")
			return
		}
		value := "false"
		if in.Strict {
			value = "true"
		}
		if err := s.saveRootPassword("account-isolation", 0, "Account isolation", value); err != nil {
			fail(w, 500, "保存失败")
			return
		}
	}
	entries := []AccountEgress{}
	s.credentials.mu.RLock()
	for key, value := range s.credentials.accounts {
		if strings.HasPrefix(key, "account-egress-") {
			var item AccountEgress
			if json.Unmarshal([]byte(value.Token), &item) != nil {
				s.credentials.mu.RUnlock()
				fail(w, 500, "出口历史损坏")
				return
			}
			entries = append(entries, item)
		}
	}
	s.credentials.mu.RUnlock()
	send(w, 200, map[string]any{"strict": s.isolationEnabled(), "history": entries})
}
func (s *Server) accountEgressAPI(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("id")
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "账号不存在")
		return
	}
	ip, err := s.verifyAccountEgress(r.Context(), account)
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	send(w, 200, map[string]string{"ip": ip, "account_id": account})
}

func (s *Server) egressConflicts(ip, excludeAccount string) ([]egressConflict, error) {
	accountNames := map[string]string{"legacy": "默认账号 (.env)"}
	if s.accounts != nil {
		for _, managed := range s.accounts.list() {
			accountNames[managed.ID] = managed.Name
		}
	}
	conflicts := make([]egressConflict, 0)
	store := s.credentials
	store.mu.RLock()
	defer store.mu.RUnlock()
	seen := map[string]bool{}
	for key, record := range store.accounts {
		if !strings.HasPrefix(key, "account-egress-") {
			continue
		}
		var history AccountEgress
		if json.Unmarshal([]byte(record.Token), &history) != nil {
			return nil, errors.New("账号出口记录损坏，无法验证代理独占性")
		}
		if history.Account == excludeAccount {
			continue
		}
		for _, used := range history.Records {
			if used.IP != ip {
				continue
			}
			key := history.Account + "\x00" + used.Proxy
			if seen[key] {
				continue
			}
			seen[key] = true
			name := accountNames[history.Account]
			if name == "" {
				name = history.Account
			}
			conflicts = append(conflicts, egressConflict{AccountID: history.Account, AccountName: name, Proxy: used.Proxy})
		}
	}
	return conflicts, nil
}

// proxyPoolEgressTestAPI checks a pool proxy's real public exit before the user
// binds it or sends any Linode API request. It never receives a Linode token
// and does not add a record to an account's usage history.
func (s *Server) proxyPoolEgressTestAPI(w http.ResponseWriter, r *http.Request) {
	if s.credentials == nil {
		fail(w, 503, "代理加密存储未配置")
		return
	}
	account := r.URL.Query().Get("account_id")
	if account == "" {
		fail(w, 400, "请先选择要绑定代理的账号")
		return
	}
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "账号不存在")
		return
	}
	proxyID := r.PathValue("id")
	raw, ok := s.poolURL(proxyID)
	if !ok {
		fail(w, 404, "代理不存在，请刷新代理池")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	ip, err := s.lookupEgress(ctx, raw)
	if err != nil {
		fail(w, 502, "代理出口检测失败："+safeProxyFailure(err))
		return
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || parsed.To4() == nil {
		fail(w, 502, "代理出口检测未返回有效公网 IP")
		return
	}
	ip = parsed.String()
	ipv6 := ""
	if value, v6err := s.lookupEgressIPv6(ctx, raw); v6err == nil {
		if parsed6 := net.ParseIP(strings.TrimSpace(value)); parsed6 != nil && parsed6.IsGlobalUnicast() && !parsed6.IsPrivate() && parsed6.To4() == nil {
			ipv6 = parsed6.String()
		}
	}
	store := s.credentials
	store.mu.RLock()
	endpoint, endpointErr := proxyEndpointLocked(store, "pool:"+proxyID)
	if endpointErr != nil {
		store.mu.RUnlock()
		fail(w, 409, "代理池地址无效，请检查代理配置")
		return
	}
	store.mu.RUnlock()
	conflicts := []egressConflict{}
	for _, detectedIP := range []string{ip, ipv6} {
		if detectedIP == "" {
			continue
		}
		found, conflictErr := s.egressConflicts(detectedIP, account)
		if conflictErr != nil {
			fail(w, 500, conflictErr.Error())
			return
		}
		for _, conflict := range found {
			duplicate := false
			for _, existing := range conflicts {
				if existing.AccountID == conflict.AccountID && existing.Proxy == conflict.Proxy {
					duplicate = true
					break
				}
			}
			if !duplicate {
				conflicts = append(conflicts, conflict)
			}
		}
	}
	send(w, 200, map[string]any{
		"ip": ip, "ipv4": ip, "ipv6": ipv6, "proxy": endpoint, "available": len(conflicts) == 0,
		"conflicts": conflicts,
	})
}
