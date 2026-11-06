package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type proxyContextKey struct{}

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
			fail(w, 500, "代理保存失败，原配置保留")
			return
		}
		send(w, 200, map[string]bool{"configured": true})
		return
	case "DELETE":
		if _, ok := s.proxyURL(account); ok {
			if err := s.credentials.remove("linode-proxy-" + account + "/0"); err != nil {
				fail(w, 500, "无法删除代理")
				return
			}
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
