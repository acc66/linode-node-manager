package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestProxyPoolEgressCanBeCheckedBeforeBinding(t *testing.T) {
	s, ids := newRefillTestServer(t)
	entries, _ := json.Marshal([]poolProxy{
		{ID: "shared", Name: "shared exit", URL: "http://user:secret@proxy.example:40001"},
		{ID: "unique", Name: "unique exit", URL: "http://user:secret@proxy.example:40002"},
	})
	if err := s.saveRootPassword("proxy-pool", 0, "pool", string(entries)); err != nil {
		t.Fatal(err)
	}
	s.egressLookup = func(_ context.Context, raw string) (string, error) {
		if strings.Contains(raw, ":40002") {
			return "203.0.113.55", nil
		}
		if strings.Contains(raw, "first.example") || strings.Contains(raw, ":40001") {
			return "203.0.113.10", nil
		}
		return "203.0.113.20", nil
	}
	if _, err := s.verifyAccountEgress(context.Background(), ids[0]); err != nil {
		t.Fatal(err)
	}
	h := newHandler(s)
	shared := apiRequest(h, http.MethodPost, "/api/proxy-pool/shared/test-egress?account_id="+ids[1], `{}`)
	var sharedResult struct {
		IP        string `json:"ip"`
		Available bool   `json:"available"`
		Conflicts []struct {
			AccountName string `json:"account_name"`
			Proxy       string `json:"proxy"`
		} `json:"conflicts"`
	}
	if err := json.Unmarshal(shared.Body.Bytes(), &sharedResult); err != nil {
		t.Fatal(err)
	}
	if shared.Code != http.StatusOK || sharedResult.Available || sharedResult.IP != "203.0.113.10" || len(sharedResult.Conflicts) != 1 || sharedResult.Conflicts[0].AccountName != "first" {
		t.Fatalf("shared proxy egress should identify its owner: %d %s", shared.Code, shared.Body.String())
	}
	if strings.Contains(shared.Body.String(), "secret") {
		t.Fatal("proxy test response exposed credentials")
	}
	unique := apiRequest(h, http.MethodPost, "/api/proxy-pool/unique/test-egress?account_id="+ids[1], `{}`)
	var uniqueResult struct {
		IP        string `json:"ip"`
		Available bool   `json:"available"`
	}
	if err := json.Unmarshal(unique.Body.Bytes(), &uniqueResult); err != nil {
		t.Fatal(err)
	}
	if unique.Code != http.StatusOK || !uniqueResult.Available || uniqueResult.IP != "203.0.113.55" {
		t.Fatalf("unique proxy egress should be available: %d %s", unique.Code, unique.Body.String())
	}
	if _, ok := s.credentials.token("account-egress-" + ids[1] + "/0"); ok {
		t.Fatal("pre-bind egress test unexpectedly recorded account usage")
	}
}
