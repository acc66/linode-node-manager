package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestProxyPoolEditPreservesSecretsBindingsAndRejectsConflicts(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	h := newHandler(s)
	if w := apiRequest(h, "POST", "/api/proxy-pool", `{"lines":"A|http://user:secret@one.example:8080\nB|socks5://two.example:1080"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	entries := s.proxyPool()
	for i, account := range []string{"a", "b"} {
		if err := s.saveProxyConfig(account, "pool:"+entries[i].ID); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/proxy-pool/" + entries[0].ID
	w := apiRequest(h, "PATCH", path, `{"name":"Renamed","url":""}`)
	if w.Code != 200 || s.proxyPool()[0].Name != "Renamed" {
		t.Fatal("rename failed:", w.Body.String())
	}
	if raw, _ := s.proxyURL("a"); raw != entries[0].URL {
		t.Fatal("rename erased proxy credentials")
	}
	w = apiRequest(h, "PATCH", path, `{"name":"must-not-save","url":"http://different:password@two.example:1080"}`)
	if w.Code != 409 || s.proxyPool()[0].Name != "Renamed" || s.proxyPool()[0].URL != entries[0].URL {
		t.Fatal("conflicting edit changed original data")
	}
	w = apiRequest(h, "PATCH", path, `{"name":"Updated","url":"https://newuser:newsecret@new.example:8443"}`)
	if w.Code != 200 {
		t.Fatal("valid edit failed:", w.Body.String())
	}
	if raw, _ := s.proxyURL("a"); raw != "https://newuser:newsecret@new.example:8443" {
		t.Fatal("bound account did not follow edited proxy")
	}
	if raw, _ := s.proxyURL("b"); raw != entries[1].URL {
		t.Fatal("editing one entry changed another binding")
	}
	for _, body := range []string{`{}`, `{"name":""}`, `{"url":"invalid"}`, `{"name":"x","extra":true}`, `{"name":"x"} {}`} {
		if w := apiRequest(h, "PATCH", path, body); w.Code != 400 {
			t.Fatalf("invalid edit accepted: %s %d", body, w.Code)
		}
	}
	if w := apiRequest(h, "PATCH", "/api/proxy-pool/missing", `{"name":"x"}`); w.Code != 404 {
		t.Fatal("missing proxy was not rejected")
	}
	w = apiRequest(h, "GET", "/api/proxy-pool", "")
	if strings.Contains(w.Body.String(), "newsecret") || strings.Contains(w.Body.String(), "newuser") {
		t.Fatal("edited proxy credentials leaked")
	}
	s.credentials.file = "/dev/null/invalid"
	if w := apiRequest(h, "PATCH", path, `{"name":"lost","url":"http://lost.example:80"}`); w.Code != 500 {
		t.Fatal("expected failed persistence")
	}
	if s.proxyPool()[0].Name != "Updated" {
		t.Fatal("failed persistence did not restore original proxy")
	}
}

func TestProxyPoolConcurrentImportAndEditDoNotLoseUpdates(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	h := newHandler(s)
	if w := apiRequest(h, "POST", "/api/proxy-pool", `{"lines":"A|http://one.example:8080"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	id := s.proxyPool()[0].ID
	var wg sync.WaitGroup
	results := make(chan int, 21)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"lines":"import-%d|http://proxy-%d.example:8080"}`, i, i)
			results <- apiRequest(h, "POST", "/api/proxy-pool", body).Code
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- apiRequest(h, "PATCH", "/api/proxy-pool/"+id, `{"name":"edited"}`).Code
	}()
	wg.Wait()
	close(results)
	for status := range results {
		if status != 200 {
			t.Fatalf("concurrent operation failed: %d", status)
		}
	}
	entries := s.proxyPool()
	if len(entries) != 21 || entries[0].Name != "edited" {
		t.Fatal("concurrent import or edit was overwritten")
	}
}
