package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBrowserFormRememberedSessionAndLogout(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "operator")
	t.Setenv("ADMIN_PASSWORD", "very-strong-test-password")
	h := newHandler(testServer(http.DefaultClient))
	login := func(remember, password string) *httptest.ResponseRecorder {
		body := url.Values{"username": {"operator"}, "password": {password}, "remember": {remember}}.Encode()
		r := httptest.NewRequest("POST", "https://panel.example.com/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://panel.example.com")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest("GET", "https://panel.example.com/login", nil))
	if got := page.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("login forms must preserve their same-origin Origin header: %q", got)
	}
	for _, field := range []string{`autocomplete="username"`, `autocomplete="current-password"`, `method="post"`, `name="remember"`} {
		if !strings.Contains(page.Body.String(), field) {
			t.Fatal("login form missing password manager support:", field)
		}
	}
	wrong := login("on", "wrong-password")
	if wrong.Code != 401 || len(wrong.Result().Cookies()) != 0 || strings.Contains(wrong.Body.String(), "wrong-password") {
		t.Fatal("invalid login leaked password or created a session")
	}
	w := login("on", "very-strong-test-password")
	if w.Code != 303 || w.Header().Get("Location") != "/" || len(w.Result().Cookies()) != 1 {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 30*24*3600 || strings.Contains(cookie.Value, "password") {
		t.Fatalf("invalid remembered session cookie: %+v", cookie)
	}
	for _, path := range []string{"/", "/api/health"} {
		r := httptest.NewRequest("GET", "https://panel.example.com"+path, nil)
		r.AddCookie(cookie)
		response := httptest.NewRecorder()
		// A fresh handler has no in-memory session state, as after a restart.
		newHandler(testServer(http.DefaultClient)).ServeHTTP(response, r)
		if response.Code != 200 {
			t.Fatalf("remembered session failed after restart: %s %d", path, response.Code)
		}
	}
	transient := login("", "very-strong-test-password").Result().Cookies()[0]
	if transient.MaxAge != 0 || !transient.Expires.IsZero() {
		t.Fatal("unchecked remember option persisted the cookie")
	}
	r := httptest.NewRequest("POST", "https://panel.example.com/api/logout", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://panel.example.com")
	r.AddCookie(cookie)
	logout := httptest.NewRecorder()
	h.ServeHTTP(logout, r)
	if logout.Code != 200 || logout.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear the remembered cookie")
	}
	if response := authRequest(h, "GET", "/api/health", "", "", ""); response.Code != 401 || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("unauthenticated API must return JSON 401 without opening Basic Auth popup")
	}
}

func TestBrowserSessionTamperingExpiryPasswordChangeAndOrigin(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "operator")
	t.Setenv("ADMIN_PASSWORD", "very-strong-test-password")
	good := signBrowserSession(browserSession{User: "operator", Expires: time.Now().Add(time.Hour).Unix(), Nonce: "test-nonce"})
	for _, value := range []string{
		good + "tampered",
		signBrowserSession(browserSession{User: "operator", Expires: time.Now().Add(-time.Hour).Unix(), Nonce: "test-nonce"}),
		signBrowserSession(browserSession{User: "another-user", Expires: time.Now().Add(time.Hour).Unix(), Nonce: "test-nonce"}),
	} {
		r := httptest.NewRequest("GET", "https://panel.example.com/api/health", nil)
		r.AddCookie(&http.Cookie{Name: browserCookieName, Value: value})
		if validBrowserSession(r) {
			t.Fatal("invalid cookie was accepted")
		}
	}
	r := httptest.NewRequest("GET", "https://panel.example.com/api/health", nil)
	r.AddCookie(&http.Cookie{Name: browserCookieName, Value: good})
	t.Setenv("ADMIN_PASSWORD", "a-new-strong-test-password")
	if validBrowserSession(r) {
		t.Fatal("password rotation did not invalidate old sessions")
	}
	h := newHandler(testServer(http.DefaultClient))
	for _, path := range []string{"/login", "/api/logout"} {
		request := httptest.NewRequest("POST", "https://panel.example.com"+path, strings.NewReader("{}"))
		request.Header.Set("Origin", "https://evil.example")
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: browserCookieName, Value: signBrowserSession(browserSession{User: "operator", Expires: time.Now().Add(time.Hour).Unix(), Nonce: "nonce"})})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request)
		if w.Code != 403 {
			t.Fatalf("cross-origin %s accepted: %d", path, w.Code)
		}
	}
}

func TestBrowserLoginBehindProxyWithRewrittenHost(t *testing.T) {
	t.Setenv("ADMIN_USERNAME", "operator")
	t.Setenv("ADMIN_PASSWORD", "very-strong-test-password")
	t.Setenv("PANEL_DOMAIN", "ld.seox9.com")
	h := newHandler(testServer(http.DefaultClient))
	form := url.Values{"username": {"operator"}, "password": {"very-strong-test-password"}}.Encode()
	r := httptest.NewRequest("POST", "http://manager:8000/login", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://ld.seox9.com")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || len(w.Result().Cookies()) != 1 {
		t.Fatalf("proxied login failed: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly {
		t.Fatal("proxied login must retain secure cookie attributes")
	}
	for _, path := range []string{"/", "/api/health", "/api/logout"} {
		method := "GET"
		if path == "/api/logout" {
			method = "POST"
		}
		request := httptest.NewRequest(method, "http://manager:8000"+path, strings.NewReader("{}"))
		request.Header.Set("Origin", "https://ld.seox9.com")
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("proxied session %s failed: %d %s", path, response.Code, response.Body.String())
		}
	}
}

func TestBrowserConfiguredOriginProtection(t *testing.T) {
	for _, tc := range []struct {
		name, domain, origin, site, forwarded string
		want                                  bool
	}{
		{name: "public origin", domain: "ld.seox9.com", origin: "https://ld.seox9.com", want: true},
		{name: "default TLS port", domain: "ld.seox9.com:443", origin: "https://LD.seox9.com", want: true},
		{name: "custom port", domain: "ld.seox9.com:8443", origin: "https://ld.seox9.com:8443", want: true},
		{name: "wrong port", domain: "ld.seox9.com", origin: "https://ld.seox9.com:8443"},
		{name: "cross site", domain: "ld.seox9.com", origin: "https://ld.seox9.com", site: "cross-site"},
		{name: "insecure origin", domain: "ld.seox9.com", origin: "http://ld.seox9.com"},
		{name: "untrusted domain", domain: "ld.seox9.com", origin: "https://evil.example"},
		{name: "forged forwarded host", origin: "https://evil.example", forwarded: "evil.example"},
		{name: "domain prefix", domain: "ld.seox9.com", origin: "https://ld.seox9.com.evil.example"},
		{name: "origin userinfo", domain: "ld.seox9.com", origin: "https://user@ld.seox9.com"},
		{name: "origin path", domain: "ld.seox9.com", origin: "https://ld.seox9.com/path"},
		{name: "unconfigured", origin: "https://ld.seox9.com"},
		{name: "invalid domain config", domain: "ld.seox9.com/path", origin: "https://ld.seox9.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PANEL_DOMAIN", tc.domain)
			r := httptest.NewRequest("POST", "http://manager:8000/login", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			r.Header.Set("X-Forwarded-Host", tc.forwarded)
			if got := sameBrowserOrigin(r); got != tc.want {
				t.Fatalf("sameBrowserOrigin = %v, want %v", got, tc.want)
			}
		})
	}
}
