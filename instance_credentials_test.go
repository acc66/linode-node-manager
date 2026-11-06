package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedPasswordsAndDeletion(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	file := filepath.Join(t.TempDir(), "credentials.enc")
	key := strings.Repeat("k", 40)
	store, err := initAccounts(file, key)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "DELETE" || r.URL.Path != "/v4/linode/instances/99" || r.Header.Get("Authorization") != "Bearer mock" {
			t.Error("incorrect delete target")
		}
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	s.credentials = store
	if err := s.saveRootPassword("legacy", 99, "test-node", "secret-root-password"); err != nil {
		t.Fatal(err)
	}
	if err := s.saveRootPassword("other-account", 99, "other-node", "different-password"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-root-password") {
		t.Fatal("password saved in plaintext")
	}
	s.credentials, err = initAccounts(file, key)
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(s)
	w := apiRequest(h, "GET", "/api/instances/99/password?account_id=legacy", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "secret-root-password") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("read password: %d", w.Code)
	}
	if w := apiRequest(h, "DELETE", "/api/instances/99?account_id=legacy", ""); w.Code != 400 {
		t.Fatalf("missing confirmation: %d", w.Code)
	}
	if calls != 0 {
		t.Fatal("unconfirmed deletion reached upstream")
	}
	if w := apiRequest(h, "DELETE", "/api/instances/99?account_id=legacy&confirm_id=99", ""); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if calls != 1 || s.passwordSaved("legacy", 99) || !s.passwordSaved("other-account", 99) {
		t.Fatal("deletion crossed account boundary or did not clear password")
	}
	reloaded, err := initAccounts(file, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.token("legacy/99"); ok {
		t.Fatal("password deletion not persisted")
	}
}
func TestWP2NullIsNotAnEmptyNodeList(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("WP2_API_TOKEN", "mock")
	t.Setenv("WP2_NODES_PATH", "/mod_mu/nodes")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ret":1,"data":null}`)) }))
	defer upstream.Close()
	t.Setenv("WP2_BASE_URL", upstream.URL)
	w := apiRequest(newHandler(testServer(upstream.Client())), "GET", "/api/wp2/nodes", "")
	if w.Code != 502 {
		t.Fatalf("null data must not be reported as zero nodes: %d", w.Code)
	}
}

func TestWP2ManagerViewIncludesModernAndUnprovisionedNodes(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("WP2_API_TOKEN", "mock")
	t.Setenv("WP2_NODES_PATH", "/mod_mu/nodes")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("view") != "manager" || r.URL.Query().Get("key") != "mock" {
			t.Error("manager view or authentication missing")
		}
		w.Write([]byte(`{"ret":1,"manager_view":true,"data":[{"id":15,"name":"Hysteria2","sort":15,"node_ip":null,"password":"hidden"},{"id":18,"name":"VLESS","sort":18,"node_ip":null}]}`))
	}))
	defer upstream.Close()
	t.Setenv("WP2_BASE_URL", upstream.URL)
	w := apiRequest(newHandler(testServer(upstream.Client())), "GET", "/api/wp2/nodes", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Hysteria2") || !strings.Contains(w.Body.String(), "VLESS") || !strings.Contains(w.Body.String(), `"manager_view":true`) {
		t.Fatalf("management nodes: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "hidden") || strings.Contains(w.Body.String(), "node_ip") {
		t.Fatal("node configuration leaked")
	}
}

func TestSavePasswordForExistingInstanceIsEncrypted(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "")
	accounts, err := initAccounts(filepath.Join(t.TempDir(), "accounts.enc"), strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	account, err := accounts.add("existing", strings.Repeat("t", 40))
	if err != nil {
		t.Fatal(err)
	}
	credentialsFile := filepath.Join(t.TempDir(), "credentials.enc")
	credentials, err := initAccounts(credentialsFile, strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v4/linode/instances/99" {
			t.Errorf("unexpected verification request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 40) {
			t.Error("wrong account token")
		}
		_, _ = w.Write([]byte(`{"id":99,"label":"pre-existing","status":"running"}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	s.accounts, s.credentials = accounts, credentials
	password := "existing-root-password-123!"
	w := apiRequest(newHandler(s), http.MethodPut, "/api/instances/99/password?account_id="+account.ID, `{"root_pass":"`+password+`"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"password_saved":true`) {
		t.Fatalf("save password: %d %s", w.Code, w.Body.String())
	}
	if got, ok := credentials.token(account.ID + "/99"); !ok || got != password {
		t.Fatal("password was not stored under the selected account and instance")
	}
	raw, err := os.ReadFile(credentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), password) || strings.Contains(w.Body.String(), password) {
		t.Fatal("password leaked in storage or response")
	}
	if w := apiRequest(newHandler(s), http.MethodPut, "/api/instances/99/password?account_id="+account.ID, `{"root_pass":"short"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("short password status: %d", w.Code)
	}
}
