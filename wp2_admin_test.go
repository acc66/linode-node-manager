package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWP2AdminLoginSyncPersistenceAndDisconnect(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	file := filepath.Join(t.TempDir(), "secrets.enc")
	key := strings.Repeat("k", 40)
	store, err := initAccounts(file, key)
	if err != nil {
		t.Fatal(err)
	}
	expired := false
	adminCalls := 0
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("wrong request method: %s", r.Method)
		}
		r.ParseForm()
		switch r.URL.Path {
		case "/auth/login":
			if r.Form.Get("email") != "admin@example.com" || r.Form.Get("passwd") != "private-password" || r.Form.Get("code") != "123456" {
				t.Error("wrong login fields")
			}
			http.SetCookie(w, &http.Cookie{Name: "auth", Value: "private-cookie", Path: "/", Secure: true, HttpOnly: true})
			w.Write([]byte(`{"ret":1,"msg":"登录成功"}`))
		case "/admin/node/ajax":
			adminCalls++
			cookie, err := r.Cookie("auth")
			if err != nil || cookie.Value != "private-cookie" {
				t.Error("session cookie missing")
			}
			if expired {
				w.Header().Set("Location", "/auth/loke")
				w.WriteHeader(302)
				return
			}
			if r.Form.Get("columns[0][data]") != "id" || r.Form.Get("order[0][dir]") != "asc" || r.Form.Get("length") != "100" {
				t.Error("incorrect DataTables fields")
			}
			data := []map[string]any{}
			if r.Form.Get("start") == "0" {
				for id := 1; id <= 100; id++ {
					data = append(data, map[string]any{"id": id, "name": "node", "sort": "Hysteria 2", "node_ip": "192.0.2.1", "server": "private-config"})
				}
			} else if r.Form.Get("start") == "100" {
				data = append(data, map[string]any{"id": 101, "name": "last node", "sort": "VLESS", "node_ip": ""})
			} else {
				t.Error("incorrect page offset")
			}
			json.NewEncoder(w).Encode(map[string]any{"recordsFiltered": 101, "data": data})
		default:
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
		}
	}))
	defer upstream.Close()
	t.Setenv("WP2_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	s.credentials = store
	h := newHandler(s)
	w := apiRequest(h, "POST", "/api/wp2/session", `{"email":"admin@example.com","password":"private-password","code":"123456"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"connected":true`) {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private-cookie") || strings.Contains(string(raw), "private-password") {
		t.Fatal("secrets written in plaintext")
	}
	s.credentials, err = initAccounts(file, key)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := s.credentials.token(wp2SessionID)
	if strings.Contains(saved, "private-password") {
		t.Fatal("login password persisted")
	}
	w = apiRequest(h, "GET", "/api/wp2/nodes", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "last node") || strings.Contains(w.Body.String(), "private-config") || strings.Contains(w.Body.String(), "private-cookie") {
		t.Fatalf("node sync: %d", w.Code)
	}
	var result struct {
		Nodes []map[string]any `json:"nodes"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Nodes) != 101 || adminCalls != 4 {
		t.Fatalf("pagination failed: nodes=%d calls=%d", len(result.Nodes), adminCalls)
	}
	expired = true
	w = apiRequest(h, "GET", "/api/wp2/nodes", "")
	if w.Code != 409 {
		t.Fatalf("expired session expected 409 without Basic Auth challenge: %d", w.Code)
	}
	if w := apiRequest(h, "DELETE", "/api/wp2/session", ""); w.Code != 200 {
		t.Fatalf("disconnect %d", w.Code)
	}
	s.credentials, err = initAccounts(file, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.credentials.token(wp2SessionID); ok {
		t.Fatal("session not deleted from disk")
	}
}
func TestWP2AdminLoginFailuresDoNotPersist(t *testing.T) {
	for _, tc := range []struct {
		name, response    string
		cookie            bool
		adminStatus, want int
	}{
		{"wrong password", `{"ret":0,"msg":"wrong password"}`, false, 0, 400},
		{"two factor", `{"ret":2}`, false, 0, 409},
		{"captcha", `{"ret":0,"msg":"请点击按钮进行验证"}`, false, 0, 409},
		{"no cookie", `{"ret":1}`, false, 0, 502},
		{"non admin", `{"ret":1}`, true, 302, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ADMIN_TOKEN", "ci-admin")
			store, err := initAccounts(filepath.Join(t.TempDir(), "session.enc"), strings.Repeat("k", 40))
			if err != nil {
				t.Fatal(err)
			}
			upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth/login" {
					if tc.cookie {
						http.SetCookie(w, &http.Cookie{Name: "auth", Value: "cookie", Path: "/", Secure: true})
					}
					w.Write([]byte(tc.response))
					return
				}
				if r.URL.Path == "/admin/node/ajax" {
					w.Header().Set("Location", "/user")
					w.WriteHeader(tc.adminStatus)
					return
				}
				t.Error("redirect must not be followed")
			}))
			defer upstream.Close()
			t.Setenv("WP2_BASE_URL", upstream.URL)
			s := testServer(upstream.Client())
			s.credentials = store
			w := apiRequest(newHandler(s), "POST", "/api/wp2/session", `{"email":"a@example.com","password":"password"}`)
			if w.Code != tc.want {
				t.Fatalf("expected %d got %d %s", tc.want, w.Code, w.Body.String())
			}
			if _, ok := store.token(wp2SessionID); ok {
				t.Fatal("failed session saved")
			}
		})
	}
}
