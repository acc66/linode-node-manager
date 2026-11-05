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
	return s.credentials.token("linode-proxy-" + account + "/0")
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
		send(w, 200, map[string]any{"configured": ok, "address": address})
		return
	case "PUT":
		var in struct {
			URL string `json:"url"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in) != nil {
			fail(w, 400, "Invalid proxy configuration")
			return
		}
		u, err := validateProxyURL(in.URL)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err := s.saveRootPassword("linode-proxy-"+account, 0, "Linode API proxy", u.String()); err != nil {
			fail(w, 500, "无法加密保存代理，请检查 ACCOUNT_ENCRYPTION_KEY")
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
