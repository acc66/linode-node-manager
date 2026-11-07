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
	client, err := proxyClient(s.client, raw)
	if err != nil {
		return "", err
	}
	defer client.CloseIdleConnections()
	client.Timeout = 12 * time.Second
	endpoint := env("EGRESS_CHECK_URL", "https://api.ipify.org?format=json")
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
	if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
		return "", errors.New("代理出口 IP 无效")
	}
	ip = parsed.String()
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
				return "", errors.New("该出口 IP 已被其他账号使用，已阻止 Linode 请求；请更换独立出口")
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
