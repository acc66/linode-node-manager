package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinodeProxyEncryptedAndOptional(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	file := filepath.Join(t.TempDir(), "secrets.enc")
	store, err := initAccounts(file, strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	upstreamCalls := 0
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Write([]byte(`{"pages":1,"data":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	s.credentials = store
	h := newHandler(s)
	w := apiRequest(h, "GET", "/api/instances?account_id=legacy&use_proxy=true", "")
	if w.Code != 502 || upstreamCalls != 0 {
		t.Fatalf("missing proxy must not fall back to direct: %d, calls=%d", w.Code, upstreamCalls)
	}
	w = apiRequest(h, "PUT", "/api/linode/proxy?account_id=legacy", `{"url":"socks5://username:private-proxy-password@proxy.example.com:1080"}`)
	if w.Code != 200 {
		t.Fatalf("proxy save: %d %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private-proxy-password") {
		t.Fatal("proxy saved unencrypted")
	}
	w = apiRequest(h, "GET", "/api/linode/proxy?account_id=legacy", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "username") || strings.Contains(w.Body.String(), "private-proxy-password") {
		t.Fatal("proxy credentials returned to browser")
	}
	if w := apiRequest(h, "GET", "/api/instances?account_id=legacy", ""); w.Code != 200 || upstreamCalls != 1 {
		t.Fatal("direct request should ignore saved proxy")
	}
	for _, address := range []string{"http://user:pass@proxy.example:8080", "https://proxy.example:443", "socks5://user:pass@proxy.example:1080", "socks5h://proxy.example:1080"} {
		client, err := proxyClient(http.DefaultClient, address)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("GET", "https://api.linode.com/v4", nil)
		proxy, err := client.Transport.(*http.Transport).Proxy(request)
		if err != nil || proxy.String() != address {
			t.Fatalf("wrong proxy selection: %v %v", proxy, err)
		}
		if err := client.CheckRedirect(request, nil); err != http.ErrUseLastResponse {
			t.Fatal("redirect would expose account credentials")
		}
		client.CloseIdleConnections()
	}
	if w := apiRequest(h, "DELETE", "/api/linode/proxy?account_id=legacy", ""); w.Code != 200 {
		t.Fatal("delete proxy failed")
	}
	if _, ok := s.proxyURL("legacy"); ok {
		t.Fatal("deleted proxy remains saved")
	}
}
func TestProxyValidation(t *testing.T) {
	for _, raw := range []string{"http://proxy", "file:///tmp/proxy", "socks5://proxy:65536", "http://proxy:0", "http://proxy:8080/path", "http://proxy:8080?secret=x"} {
		if _, err := validateProxyURL(raw); err == nil {
			t.Errorf("accepted invalid proxy %q", raw)
		}
	}
}
func TestRemoveDefaultAccountDoesNotCallLinode(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	store, _ := initAccounts(filepath.Join(t.TempDir(), "accounts.enc"), strings.Repeat("k", 40))
	secrets, _ := initAccounts(filepath.Join(t.TempDir(), "secrets.enc"), strings.Repeat("k", 40))
	s := testServer(http.DefaultClient)
	s.accounts = store
	s.credentials = secrets
	w := apiRequest(newHandler(s), "DELETE", "/api/accounts/legacy", "")
	if w.Code != 200 || s.legacyEnabled() {
		t.Fatalf("default account not removed: %d", w.Code)
	}
	if _, err := s.accountToken("legacy"); err == nil {
		t.Fatal("removed account still usable")
	}
	if os.Getenv("LINODE_TOKEN") != "mock" {
		t.Fatal("removal mutated original token")
	}
}
