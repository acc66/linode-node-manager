package main

import (
	"net/http/httptest"
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
