package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestBulkAccountImportBindingAndDelete(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	var err error
	s.accounts, err = initAccounts(t.TempDir()+"/accounts.enc", strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(s)

	imported := apiRequest(h, http.MethodPost, "/api/accounts/bulk", `{"accounts":[{"name":"日本 A","token":"`+strings.Repeat("x", 40)+`"},{"name":"日本 B","token":"`+strings.Repeat("y", 40)+`"}]}`)
	if imported.Code != http.StatusCreated {
		t.Fatalf("bulk import: %d %s", imported.Code, imported.Body.String())
	}
	var result struct {
		Created []ManagedAccount `json:"created"`
		Count   int              `json:"count"`
	}
	if json.Unmarshal(imported.Body.Bytes(), &result) != nil || result.Count != 2 {
		t.Fatalf("unexpected import result: %s", imported.Body.String())
	}
	if strings.Contains(imported.Body.String(), strings.Repeat("x", 40)) || len(s.accounts.list()) != 2 {
		t.Fatal("tokens leaked or accounts missing")
	}
	bad := apiRequest(h, http.MethodPost, "/api/accounts/bulk", `{"accounts":[{"name":"new","token":"`+strings.Repeat("z", 40)+`"},{"name":"new","token":"`+strings.Repeat("q", 40)+`"}]}`)
	if bad.Code != http.StatusConflict || len(s.accounts.list()) != 2 {
		t.Fatalf("duplicate batch was partially imported: %d %s", bad.Code, bad.Body.String())
	}

	if w := apiRequest(h, http.MethodPost, "/api/proxy-pool", `{"lines":"proxy-a|socks5://user:secret@a.example:1080\nproxy-b|socks5://user:secret@b.example:1080"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	proxies := s.proxyPool()
	body, _ := json.Marshal(map[string]any{"bindings": []map[string]string{{"account_id": result.Created[0].ID, "proxy_id": proxies[0].ID}, {"account_id": result.Created[1].ID, "proxy_id": proxies[1].ID}}})
	if w := apiRequest(h, http.MethodPut, "/api/account-pool/bindings", string(body)); w.Code != 200 {
		t.Fatalf("bulk bind: %d %s", w.Code, w.Body.String())
	}
	for i, account := range result.Created {
		if raw, ok := s.proxyURL(account.ID); !ok || raw != proxies[i].URL || !s.proxyEnabled(account.ID) {
			t.Fatalf("account %s proxy binding missing", account.Name)
		}
	}
	conflict, _ := json.Marshal(map[string]any{"bindings": []map[string]string{{"account_id": result.Created[0].ID, "proxy_id": proxies[1].ID}, {"account_id": result.Created[1].ID, "proxy_id": proxies[1].ID}}})
	if w := apiRequest(h, http.MethodPut, "/api/account-pool/bindings", string(conflict)); w.Code != http.StatusConflict {
		t.Fatalf("duplicate proxy should be rejected: %d %s", w.Code, w.Body.String())
	}
	if raw, _ := s.proxyURL(result.Created[0].ID); raw != proxies[0].URL {
		t.Fatal("failed batch changed an existing binding")
	}

	deleteBody, _ := json.Marshal(map[string][]string{"ids": {result.Created[0].ID, result.Created[1].ID}})
	if w := apiRequest(h, http.MethodDelete, "/api/accounts/bulk", string(deleteBody)); w.Code != 200 {
		t.Fatalf("bulk delete: %d %s", w.Code, w.Body.String())
	}
	if len(s.accounts.list()) != 0 {
		t.Fatal("bulk delete left accounts")
	}
	if _, ok := s.proxyURL(result.Created[0].ID); ok {
		t.Fatal("bulk delete left proxy binding")
	}
}

func TestBulkDeleteRejectsAccountsClaimedByRefillTask(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	var err error
	s.accounts, err = initAccounts(t.TempDir()+"/accounts.enc", strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.accounts.add("claimed", strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	st := RefillState{TaskID: "default", Name: "task", Config: defaultRefillConfig(), CurrentAccount: a.ID, CurrentID: 123, Stage: "ready"}
	if err := s.saveRefill(&st, ""); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string][]string{"ids": {a.ID}})
	if w := apiRequest(newHandler(s), http.MethodDelete, "/api/accounts/bulk", string(body)); w.Code != http.StatusConflict {
		t.Fatalf("claimed account deletion status %d: %s", w.Code, w.Body.String())
	}
	if _, err := s.accountToken(a.ID); err != nil {
		t.Fatal("claimed account was removed")
	}
}
