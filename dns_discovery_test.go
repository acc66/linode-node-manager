package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDNSDiscoveryMatchesNodeAndRejectsUnrelatedZone(t *testing.T) {
	for _, domain := range []string{"jp.sub.example.com", "jp.other.example"} {
		t.Run(domain, func(t *testing.T) {
			t.Setenv("ADMIN_TOKEN", "ci-admin")
			t.Setenv("WP2_API_TOKEN", "wp2-test-token")
			upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/zones":
					if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer cf-discovery-token" {
						t.Error("incorrect discovery authorization")
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"name": "example.com"}, {"name": "sub.example.com"}}})
				case "/api/v1/server/UniProxy/config":
					if r.Header.Get("Authorization") != "Bearer wp2-test-token" || r.URL.Query().Get("node_id") != "929" {
						t.Error("incorrect wp2 node request")
					}
					json.NewEncoder(w).Encode(map[string]string{"server_name": domain})
				default:
					t.Error("DNS discovery must not modify records")
				}
			}))
			defer upstream.Close()
			t.Setenv("DNS_CF_API_BASE_URL", upstream.URL)
			t.Setenv("WP2_BASE_URL", upstream.URL)
			w := apiRequest(newHandler(testServer(upstream.Client())), "POST", "/api/dns/discover", `{"provider":"cloudflare","token":"cf-discovery-token","node_id":929}`)
			if w.Code != 200 || strings.Contains(w.Body.String(), "cf-discovery-token") {
				t.Fatalf("discovery: %d %s", w.Code, w.Body.String())
			}
			var result struct {
				Zones     []string `json:"zones"`
				Suggested string   `json:"suggested_zone"`
				Message   string   `json:"message"`
			}
			json.Unmarshal(w.Body.Bytes(), &result)
			if domain == "jp.sub.example.com" {
				if result.Suggested != "sub.example.com" {
					t.Fatal("longest managed zone not selected")
				}
			} else {
				if result.Suggested != "" || result.Message == "" {
					t.Fatal("unrelated zone was suggested")
				}
			}
		})
	}
}
func TestAliDNSDiscoveryReturnsAccessibleZones(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("Action") != "DescribeDomains" || r.Form.Get("Signature") != signAli(r.Form, "ali-secret") {
			t.Error("incorrect Aliyun discovery request")
		}
		w.Write([]byte(`{"TotalCount":1,"Domains":{"Domain":[{"DomainName":"help600.com"}]}}`))
	}))
	defer upstream.Close()
	t.Setenv("DNS_ALI_API_BASE_URL", upstream.URL)
	w := apiRequest(newHandler(testServer(upstream.Client())), "POST", "/api/dns/discover", `{"provider":"alidns","access_key_id":"ali-id","access_key_secret":"ali-secret"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"suggested_zone":"help600.com"`) || strings.Contains(w.Body.String(), "ali-secret") {
		t.Fatalf("Aliyun discovery: %d %s", w.Code, w.Body.String())
	}
}
