package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type proxyContextKey struct{}

var errProxyAlreadyBound = errors.New("该代理已绑定其他账号，请先解除原账号绑定")

// Resolve pool references while the credential store lock is held. Compare
// endpoints, so duplicate imports or different credentials cannot reuse one
// proxy host and port across accounts.
func resolveProxyLocked(store *accountStore, raw string) (string, error) {
	if strings.HasPrefix(raw, "pool:") {
		var entries []poolProxy
		if json.Unmarshal([]byte(store.accounts["proxy-pool/0"].Token), &entries) != nil {
			return "", errors.New("代理池配置无效")
		}
		id := strings.TrimPrefix(raw, "pool:")
		raw = ""
		for _, entry := range entries {
			if entry.ID == id {
				raw = entry.URL
				break
			}
		}
	}
	return raw, nil
}

func proxyEndpointLocked(store *accountStore, raw string) (string, error) {
	raw, err := resolveProxyLocked(store, raw)
	if err != nil {
		return "", err
	}
	u, err := validateProxyURL(raw)
	if err != nil {
		return "", err
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port, _ := strconv.Atoi(u.Port())
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (s *Server) proxyForRequest(account string) (string, error) {
	if account == "" {
		account = "legacy"
	}
	if s.credentials == nil {
		return "", errors.New("当前账号未配置代理")
	}
	store := s.credentials
	store.mu.RLock()
	defer store.mu.RUnlock()
	record, ok := store.accounts["linode-proxy-"+account+"/0"]
	if !ok {
		return "", errors.New("当前账号未配置代理")
	}
	owners, err := proxyOwnersLocked(store, record.Token)
	if err != nil {
		return "", err
	}
	for _, owner := range owners {
		if owner != account {
			return "", errProxyAlreadyBound
		}
	}
	return resolveProxyLocked(store, record.Token)
}

func proxyOwnershipLocked(store *accountStore) map[string][]string {
	var entries []poolProxy
	_ = json.Unmarshal([]byte(store.accounts["proxy-pool/0"].Token), &entries)
	poolURLs := make(map[string]string, len(entries))
	for _, entry := range entries {
		poolURLs[entry.ID] = entry.URL
	}
	owners := map[string][]string{}
	for key, record := range store.accounts {
		if !strings.HasPrefix(key, "linode-proxy-") || strings.HasPrefix(key, "linode-proxy-enabled-") || !strings.HasSuffix(key, "/0") {
			continue
		}
		raw := record.Token
		if strings.HasPrefix(raw, "pool:") {
			raw = poolURLs[strings.TrimPrefix(raw, "pool:")]
		}
		endpoint, err := proxyEndpointLocked(store, raw)
		if err == nil {
			owners[endpoint] = append(owners[endpoint], strings.TrimSuffix(strings.TrimPrefix(key, "linode-proxy-"), "/0"))
		}
	}
	return owners
}

func proxyOwnersLocked(store *accountStore, raw string) ([]string, error) {
	endpoint, err := proxyEndpointLocked(store, raw)
	if err != nil {
		return nil, err
	}
	return proxyOwnershipLocked(store)[endpoint], nil
}

func validateProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("请输入含端口的代理地址，例如 http://用户:密码@主机:端口 或 socks5://主机:端口")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("代理端口必须在 1-65535 之间")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errors.New("代理仅支持 HTTP、HTTPS、SOCKS5 或 SOCKS5H")
	}
	return u, nil
}
func (s *Server) proxyURL(account string) (string, bool) {
	if account == "" {
		account = "legacy"
	}
	if s.credentials == nil {
		return "", false
	}
	raw, ok := s.credentials.token("linode-proxy-" + account + "/0")
	if ok && strings.HasPrefix(raw, "pool:") {
		return s.poolURL(strings.TrimPrefix(raw, "pool:"))
	}
	return raw, ok
}
func proxyClient(original *http.Client, raw string) (*http.Client, error) {
	u, err := validateProxyURL(raw)
	if err != nil {
		return nil, err
	}
	base := http.DefaultTransport.(*http.Transport)
	if existing, ok := original.Transport.(*http.Transport); ok {
		base = existing
	}
	transport := base.Clone()
	transport.Proxy = http.ProxyURL(u)
	client := *original
	client.Transport = transport
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &client, nil
}
func (s *Server) linodeProxyAPI(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account_id")
	if account == "" {
		fail(w, 400, "请先选择具体 Linode 账号")
		return
	}
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "Unknown account")
		return
	}
	switch r.Method {
	case "GET":
		raw, ok := s.proxyURL(account)
		address := ""
		if ok {
			if u, err := validateProxyURL(raw); err == nil {
				address = u.Scheme + "://" + u.Host
			}
		}
		poolID := ""
		if s.credentials != nil {
			if binding, exists := s.credentials.token("linode-proxy-" + account + "/0"); exists && strings.HasPrefix(binding, "pool:") {
				poolID = strings.TrimPrefix(binding, "pool:")
			}
		}
		send(w, 200, map[string]any{"configured": ok, "address": address, "pool_id": poolID, "enabled": ok && s.proxyEnabled(account)})
		return
	case "PUT":
		var in struct {
			URL     string `json:"url"`
			Enabled *bool  `json:"enabled"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in) != nil {
			fail(w, 400, "Invalid proxy configuration")
			return
		}
		if in.URL == "" && in.Enabled != nil {
			if *in.Enabled {
				if _, ok := s.proxyURL(account); !ok {
					fail(w, 400, "请先保存当前账号的代理")
					return
				}
				raw, _ := s.credentials.token("linode-proxy-" + account + "/0")
				if err := s.saveProxyConfig(account, raw); err != nil {
					if errors.Is(err, errProxyAlreadyBound) {
						fail(w, 409, err.Error())
					} else {
						fail(w, 500, "代理启用状态保存失败")
					}
					return
				}
				send(w, 200, map[string]bool{"saved": true})
				return
			}
			if err := s.saveRootPassword("linode-proxy-enabled-"+account, 0, "Proxy enabled", strconv.FormatBool(*in.Enabled)); err != nil {
				fail(w, 500, "代理启用状态保存失败")
				return
			}
			send(w, 200, map[string]bool{"saved": true})
			return
		}
		u, err := validateProxyURL(in.URL)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err := s.saveProxyConfig(account, u.String()); err != nil {
			if errors.Is(err, errProxyAlreadyBound) {
				fail(w, 409, err.Error())
				return
			}
			fail(w, 500, "代理保存失败，原配置保留")
			return
		}
		send(w, 200, map[string]bool{"configured": true})
		return
	case "DELETE":
		if err := s.clearProxyConfig(account); err != nil {
			fail(w, 500, "无法删除代理")
			return
		}
		send(w, 200, map[string]bool{"configured": false})
		return
	default:
		fail(w, 405, "Method not allowed")
	}
}
func useProxyContext(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, proxyContextKey{}, enabled)
}

// Classify transport errors without exposing proxy credentials or request URLs.
func safeProxyFailure(err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "407"), strings.Contains(text, "proxy authentication"):
		return "代理认证失败，请检查代理用户名和密码"
	case strings.Contains(text, "timeout"), strings.Contains(text, "deadline exceeded"):
		return "连接超时，请检查代理与 Linode API 的连通性"
	case strings.Contains(text, "connection refused"):
		return "连接被拒绝，请检查代理地址、端口和服务状态"
	case strings.Contains(text, "certificate"), strings.Contains(text, "tls"):
		return "TLS 连接或证书验证失败，请检查系统时间和证书"
	case strings.Contains(text, "no such host"):
		return "域名解析失败，请检查 DNS"
	default:
		return "网络连接失败，请检查代理协议及网络连通性"
	}
}

func (s *Server) proxyEnabled(account string) bool {
	if s.credentials == nil {
		return false
	}
	value, ok := s.credentials.token("linode-proxy-enabled-" + account + "/0")
	return !ok || value == "true"
}

func (s *Server) saveProxyConfig(account, raw string) error {
	if s.credentials == nil {
		return errors.New("encrypted storage unavailable")
	}
	store := s.credentials
	store.mu.Lock()
	defer store.mu.Unlock()
	owners, err := proxyOwnersLocked(store, raw)
	if err != nil {
		return err
	}
	for _, owner := range owners {
		if owner != account {
			return errProxyAlreadyBound
		}
	}
	key := "linode-proxy-" + account + "/0"
	enabledKey := "linode-proxy-enabled-" + account + "/0"
	previous, exists := store.accounts[key]
	previousEnabled, enabledExists := store.accounts[enabledKey]
	store.accounts[key] = storedAccount{ID: key, Name: "Linode API proxy", Token: raw}
	store.accounts[enabledKey] = storedAccount{ID: enabledKey, Name: "Proxy enabled", Token: "true"}
	if err := store.saveLocked(); err != nil {
		if exists {
			store.accounts[key] = previous
		} else {
			delete(store.accounts, key)
		}
		if enabledExists {
			store.accounts[enabledKey] = previousEnabled
		} else {
			delete(store.accounts, enabledKey)
		}
		return err
	}
	return nil
}

func (s *Server) clearProxyConfig(account string) error {
	if s.credentials == nil {
		return nil
	}
	store := s.credentials
	store.mu.Lock()
	defer store.mu.Unlock()
	key, enabledKey := "linode-proxy-"+account+"/0", "linode-proxy-enabled-"+account+"/0"
	previous, exists := store.accounts[key]
	previousEnabled, enabledExists := store.accounts[enabledKey]
	if !exists && !enabledExists {
		return nil
	}
	delete(store.accounts, key)
	delete(store.accounts, enabledKey)
	if err := store.saveLocked(); err != nil {
		if exists {
			store.accounts[key] = previous
		}
		if enabledExists {
			store.accounts[enabledKey] = previousEnabled
		}
		return err
	}
	return nil
}
