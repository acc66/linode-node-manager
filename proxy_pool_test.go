package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestProxyPoolImportAndAccountIsolation(t *testing.T) {
	store, err := initAccounts(t.TempDir()+"/credentials", strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{credentials: store}
	request := func(body string) int {
		r := httptest.NewRequest("POST", "/api/proxy-pool", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.proxyPoolAPI(w, r)
		return w.Code
	}
	if code := request(`{"lines":"A|http://a:secret@proxy.example:8080\nB|socks5://b:secret@other.example:1080"}`); code != 200 {
		t.Fatalf("import: %d", code)
	}
	entries := s.proxyPool()
	if len(entries) != 2 {
		t.Fatal("batch missing")
	}
	if code := request(`{"lines":"C|http://third.example:80\nbad"}`); code != 400 {
		t.Fatal("invalid batch accepted")
	}
	if len(s.proxyPool()) != 2 {
		t.Fatal("invalid batch partially saved")
	}
	for i, account := range []string{"a", "b"} {
		if err := s.saveProxyConfig(account, "pool:"+entries[i].ID); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := s.proxyURL("a")
	b, _ := s.proxyURL("b")
	if a == b || a != entries[0].URL || b != entries[1].URL {
		t.Fatal("account proxy bindings mixed")
	}
	w := httptest.NewRecorder()
	s.proxyPoolAPI(w, httptest.NewRequest("GET", "/api/proxy-pool", nil))
	if strings.Contains(w.Body.String(), "secret") {
		t.Fatal("pool leaks authentication")
	}
}

func TestProxyPoolAccountCreationBindingAndUnbinding(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	var err error
	s.accounts, err = initAccounts(t.TempDir()+"/accounts", strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(s)
	if w := apiRequest(h, "POST", "/api/proxy-pool", `{"lines":"A|http://user:secret@proxy.example:8080\nB|http://other.example:8080"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	entries := s.proxyPool()
	create := func(name, id string, want int) ManagedAccount {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": name, "token": strings.Repeat("a", 64), "proxy_id": id})
		w := apiRequest(h, "POST", "/api/accounts", string(body))
		if w.Code != want {
			t.Fatalf("create status %d: %s", w.Code, w.Body.String())
		}
		var a ManagedAccount
		if want == 201 {
			if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
				t.Fatal(err)
			}
		}
		return a
	}
	first := create("first", entries[0].ID, 201)
	second := create("second", "", 201)
	create("invalid", "missing-proxy", 400)
	if len(s.accounts.list()) != 2 {
		t.Fatal("invalid proxy created an account")
	}
	if raw, ok := s.proxyURL(first.ID); !ok || raw != entries[0].URL || !s.proxyEnabled(first.ID) {
		t.Fatal("creation did not bind and enable selected pool proxy")
	}
	if _, ok := s.proxyURL(second.ID); ok {
		t.Fatal("direct account inherited another account's proxy")
	}
	bind := func(account, id string, want int) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"id": id})
		w := apiRequest(h, "PUT", "/api/proxy-pool?account_id="+account, string(body))
		if w.Code != want {
			t.Fatalf("binding status %d: %s", w.Code, w.Body.String())
		}
	}
	bind(second.ID, entries[1].ID, 200)
	bind(first.ID, "missing-proxy", 400)
	bind("missing-account", entries[1].ID, 400)
	w := apiRequest(h, "GET", "/api/linode/proxy?account_id="+second.ID, "")
	var config struct {
		PoolID string `json:"pool_id"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &config) != nil || config.PoolID != entries[1].ID || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("pool binding not safely exposed: %s", w.Body.String())
	}
	bind(second.ID, "", 200)
	if _, ok := s.proxyURL(second.ID); ok {
		t.Fatal("unbound account retained proxy")
	}
	if raw, _ := s.proxyURL(first.ID); raw != entries[0].URL {
		t.Fatal("binding another account changed the first account")
	}
	if w := apiRequest(h, "PATCH", "/api/proxy-pool", `{"id":"`+entries[0].ID+`"}`); w.Code != 405 {
		t.Fatal("removed external IP test endpoint remains available")
	}
}

func TestPoolBalanceUsesSelectedAccountProxyAndToken(t *testing.T) {
	if os.Getenv("LINODE_TEST_IN_MEMORY") == "1" {
		t.Skip("requires local HTTP proxy listener")
	}
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "")
	t.Setenv("LINODE_API_BASE_URL", "http://linode.invalid/v4")
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "linode.invalid" || r.URL.Path != "/v4/account" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
			t.Error("balance query used incorrect account or endpoint")
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(`{"balance":-12.5,"balance_uninvoiced":2,"email":"private@example.com"}`))
	}))
	defer proxy.Close()
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	var err error
	s.accounts, err = initAccounts(t.TempDir()+"/accounts", strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := s.accounts.add("first", strings.Repeat("a", 64))
	second, _ := s.accounts.add("second", strings.Repeat("b", 64))
	entries, _ := json.Marshal([]poolProxy{{ID: "selected", Name: "selected", URL: proxy.URL}})
	if err := s.saveRootPassword("proxy-pool", 0, "pool", string(entries)); err != nil {
		t.Fatal(err)
	}
	if err := s.saveProxyConfig(second.ID, "pool:selected"); err != nil {
		t.Fatal(err)
	}
	w := apiRequest(newHandler(s), "GET", "/api/accounts/"+second.ID+"/billing?account_id="+first.ID+"&use_proxy=true", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"balance":-12.5`) || strings.Contains(w.Body.String(), "private@example.com") {
		t.Fatalf("selected proxy balance check failed: %d %s", w.Code, w.Body.String())
	}
}
