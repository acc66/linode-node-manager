package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const browserCookieName = "lnm_session"

type browserSession struct {
	User    string `json:"u"`
	Expires int64  `json:"e"`
	Nonce   string `json:"n"`
}

func browserSessionKey() []byte {
	key := sha256.Sum256([]byte("lnm-session-v1\x00" + os.Getenv("ADMIN_USERNAME") + "\x00" + os.Getenv("ADMIN_PASSWORD") + "\x00" + os.Getenv("ACCOUNT_ENCRYPTION_KEY")))
	return key[:]
}

func signBrowserSession(session browserSession) string {
	data, _ := json.Marshal(session)
	payload := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, browserSessionKey())
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validBrowserSession(r *http.Request) bool {
	if os.Getenv("ADMIN_USERNAME") == "" || len(os.Getenv("ADMIN_PASSWORD")) < 12 {
		return false
	}
	cookie, err := r.Cookie(browserCookieName)
	if err != nil || len(cookie.Value) > 2048 {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, browserSessionKey())
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	var session browserSession
	if err != nil || json.Unmarshal(data, &session) != nil {
		return false
	}
	return session.Expires > time.Now().Unix() && session.Nonce != "" && safeEqual(session.User, os.Getenv("ADMIN_USERNAME"))
}

func localBrowserHost(host string) bool {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func sameBrowserOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host && (u.Scheme == "https" || u.Scheme == "http" && localBrowserHost(r.Host))
	}
	return true
}

func browserSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

func browserCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{Name: browserCookieName, Path: "/", HttpOnly: true, Secure: !localBrowserHost(r.Host) || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteStrictMode}
}

func (s *Server) browserLogin(w http.ResponseWriter, r *http.Request) {
	browserSecurityHeaders(w)
	if os.Getenv("ADMIN_USERNAME") == "" || len(os.Getenv("ADMIN_PASSWORD")) < 12 {
		renderBrowserLogin(w, 503, "", "请先配置面板管理员账号与密码。", true)
		return
	}
	if r.Method == http.MethodGet {
		if validBrowserSession(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderBrowserLogin(w, 200, "", "", true)
		return
	}
	if !sameBrowserOrigin(r) {
		renderBrowserLogin(w, 403, "", "登录来源无效，请从面板地址重新打开。", true)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		renderBrowserLogin(w, 400, "", "登录信息格式无效。", true)
		return
	}
	user, pass := r.PostForm.Get("username"), r.PostForm.Get("password")
	remember := r.PostForm.Get("remember") == "on"
	if !safeEqual(user, os.Getenv("ADMIN_USERNAME")) || !safeEqual(pass, os.Getenv("ADMIN_PASSWORD")) {
		renderBrowserLogin(w, 401, user, "账号或密码错误。", remember)
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		renderBrowserLogin(w, 500, user, "暂时无法建立登录会话，请重试。", remember)
		return
	}
	ttl := 12 * time.Hour
	if remember {
		ttl = 30 * 24 * time.Hour
	}
	expires := time.Now().Add(ttl)
	cookie := browserCookie(r)
	cookie.Value = signBrowserSession(browserSession{User: user, Expires: expires.Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	if remember {
		cookie.MaxAge = int(ttl.Seconds())
		cookie.Expires = expires
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) browserLogout(w http.ResponseWriter, r *http.Request) {
	cookie := browserCookie(r)
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0)
	http.SetCookie(w, cookie)
	send(w, 200, map[string]bool{"logged_out": true})
}

func renderBrowserLogin(w http.ResponseWriter, status int, user, message string, remember bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = browserLoginTemplate.Execute(w, struct {
		User, Message string
		Remember      bool
	}{user, message, remember})
}

var browserLoginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · Linode 节点管理</title>
<style>body{margin:0;background:#0b1220;color:#e5edf8;font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center}main{box-sizing:border-box;width:min(420px,92vw);padding:32px;background:#142035;border:1px solid #2a405e;border-radius:20px}h1{font-size:24px;margin:0 0 8px}p{color:#a7b7cf;font-size:14px;line-height:1.6}label{display:block;margin-top:20px}input:not([type=checkbox]){box-sizing:border-box;width:100%;margin-top:8px;padding:13px;border:1px solid #3c5270;border-radius:9px;background:#0b1628;color:#fff;font:inherit}button{width:100%;margin-top:24px;padding:13px;border:0;border-radius:9px;background:#79b8ff;color:#081b35;font:inherit;font-weight:600}.error{color:#ffb2b9}.remember{font-size:14px}</style></head>
<body><main><h1>Linode 节点管理</h1><p>登录服务器与节点管理面板</p>
{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}
<form method="post" action="/login" autocomplete="on">
<label for="username">账号<input id="username" name="username" autocomplete="username" value="{{.User}}" required autofocus></label>
<label for="password">密码<input id="password" name="password" type="password" autocomplete="current-password" required></label>
<label class="remember"><input name="remember" type="checkbox"{{if .Remember}} checked{{end}}> 记住登录（30 天）</label>
<button type="submit">登录</button></form><p>支持浏览器保存并自动填充账号密码。记住登录后，关闭浏览器也可继续使用；退出登录可清除此设备的会话。</p></main></body></html>`))
