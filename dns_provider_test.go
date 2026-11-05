package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dnsTestStore(t *testing.T, s *Server) {
	t.Helper()
	store, err := initAccounts(filepath.Join(t.TempDir(), "secrets.enc"), strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	s.credentials = store
}
func TestDNSConfigEncryptedAndMatched(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	h := newHandler(s)
	for _, body := range []string{`{"zone":"example.com","provider":"cloudflare","token":"private-cf-token","enabled":true}`, `{"zone":"sub.example.com","provider":"alidns","access_key_id":"private-ali-id","access_key_secret":"private-ali-secret","enabled":true}`} {
		if w := apiRequest(h, "POST", "/api/dns/providers", body); w.Code != 200 {
			t.Fatalf("save DNS %d %s", w.Code, w.Body.String())
		}
	}
	raw, err := os.ReadFile(s.credentials.file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private-") {
		t.Fatal("DNS keys saved unencrypted")
	}
	w := apiRequest(h, "GET", "/api/dns/providers", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), "access_key_secret") {
		t.Fatal("DNS key leaked to browser")
	}
	selected, err := s.dnsConfigFor("a.sub.example.com")
	if err != nil || selected == nil || selected.Provider != "alidns" {
		t.Fatal("most specific zone was not matched")
	}
	selected, err = s.dnsConfigFor("evilexample.com")
	if err != nil || selected != nil {
		t.Fatal("domain boundary was not respected")
	}
	if w := apiRequest(h, "PATCH", "/api/dns/providers?zone=sub.example.com", `{"enabled":false}`); w.Code != 200 {
		t.Fatal("pause DNS failed")
	}
	selected, err = s.dnsConfigFor("a.sub.example.com")
	if err != nil || selected != nil {
		t.Fatal("disabled DNS config was still selected")
	}
	if w := apiRequest(h, "DELETE", "/api/dns/providers?zone=sub.example.com", ""); w.Code != 200 {
		t.Fatal("delete DNS config failed")
	}
}
func TestCloudflareDNSOnlyChangesExactNode(t *testing.T) {
	updates := 0
	cname := false
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-test-token" {
			t.Error("incorrect CF authorization")
		}
		var result any
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			result = []map[string]any{{"id": "zone1", "name": "example.com"}}
		case r.Method == "GET" && r.URL.Path == "/zones/zone1/dns_records":
			if r.URL.Query().Get("name") != "node.example.com" {
				t.Error("wrong DNS name filter")
			}
			if cname {
				result = []map[string]any{{"id": "alias", "name": "node.example.com", "type": "CNAME", "content": "elsewhere.example"}}
			} else {
				result = []map[string]any{{"id": "a1", "name": "node.example.com", "type": "A", "content": "192.0.2.9"}, {"id": "v6", "name": "node.example.com", "type": "AAAA", "content": "2001:db8::9"}, {"id": "other", "name": "other.example.com", "type": "A", "content": "192.0.2.10"}}
			}
		case r.Method == "PATCH" && r.URL.Path == "/zones/zone1/dns_records/a1":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["content"] != "172.104.46.26" || body["proxied"] != false || body["name"] != "node.example.com" {
				t.Error("incorrect A record update")
			}
			updates++
			result = map[string]any{"id": "a1"}
		case r.Method == "DELETE" && r.URL.Path == "/zones/zone1/dns_records/v6":
			updates++
			result = map[string]any{"id": "v6"}
		default:
			t.Errorf("unexpected DNS mutation: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer upstream.Close()
	t.Setenv("DNS_CF_API_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	config := DNSConfig{Zone: "example.com", Provider: "cloudflare", Token: "cf-test-token", Enabled: true}
	if err := s.syncCloudflare(context.Background(), config, "node.example.com", "172.104.46.26", ""); err != nil {
		t.Fatal(err)
	}
	if updates != 2 {
		t.Fatalf("expected A update and stale AAAA cleanup, got %d", updates)
	}
	cname = true
	if err := s.syncCloudflare(context.Background(), config, "node.example.com", "172.104.46.26", ""); err == nil {
		t.Fatal("CNAME conflict should stop before changes")
	}
	if updates != 2 {
		t.Fatal("CNAME was modified automatically")
	}
}
func TestAliDNSExactNodeAndSignature(t *testing.T) {
	updates := 0
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Method != "POST" || r.Form.Get("AccessKeyId") != "ali-id" || r.Form.Get("Signature") != signAli(r.Form, "ali-secret") {
			t.Error("incorrect Aliyun signed request")
		}
		var result any = map[string]any{"RequestId": "mock"}
		switch r.Form.Get("Action") {
		case "DescribeDomainRecords":
			result = map[string]any{"TotalCount": 3, "DomainRecords": map[string]any{"Record": []map[string]any{{"RecordId": "a", "RR": "node", "Type": "A", "Value": "192.0.2.9", "Status": "ENABLE"}, {"RecordId": "v6", "RR": "node", "Type": "AAAA", "Value": "2001:db8::9"}, {"RecordId": "other", "RR": "other", "Type": "A", "Value": "192.0.2.9"}}}}
		case "UpdateDomainRecord":
			if r.Form.Get("RecordId") != "a" || r.Form.Get("RR") != "node" || r.Form.Get("Value") != "172.104.46.26" {
				t.Error("wrong Aliyun record update")
			}
			updates++
		case "DeleteDomainRecord":
			if r.Form.Get("RecordId") != "v6" {
				t.Error("unrelated Aliyun record deleted")
			}
			updates++
		default:
			t.Errorf("unexpected Aliyun action %s", r.Form.Get("Action"))
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer upstream.Close()
	t.Setenv("DNS_ALI_API_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	config := DNSConfig{Zone: "example.com", Provider: "alidns", AccessKeyID: "ali-id", AccessKeySecret: "ali-secret"}
	if err := s.syncAliDNS(context.Background(), config, "node.example.com", "172.104.46.26", ""); err != nil {
		t.Fatal(err)
	}
	if updates != 2 {
		t.Fatalf("expected 2 Aliyun updates, got %d", updates)
	}
}
func TestDNSInstallProtectsRootAndPanelDomains(t *testing.T) {
	domain := "example.com"
	writes := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/server/UniProxy/config" {
			json.NewEncoder(w).Encode(map[string]any{"server_name": domain})
			return
		}
		writes++
		t.Error("protected domain reached DNS provider")
	})
	s := testServer(&http.Client{Transport: handlerTransport{handler: handler}})
	dnsTestStore(t, s)
	raw, _ := json.Marshal(DNSConfig{Zone: "example.com", Provider: "cloudflare", Token: "cf-token", Enabled: true})
	s.saveRootPassword("dns-provider-example.com", 0, "DNS", string(raw))
	for _, name := range []string{"example.com", "wp2.example.com", "panel.example.com"} {
		domain = name
		t.Setenv("PANEL_DOMAIN", "panel.example.com")
		if _, _, err := s.prepareDeploymentDNS(context.Background(), "https://wp2.example.com", "wp2-token", 929, Instance{IPv4: []string{"172.104.46.26"}}); err == nil {
			t.Errorf("protected name allowed: %s", name)
		}
	}
	if writes != 0 {
		t.Fatal("protected name mutated DNS")
	}
}
func TestAliPercentEncoding(t *testing.T) {
	if got := percentEncode("a b*~+"); got != "a%20b%2A~%2B" {
		t.Fatalf("RPC canonical encoding: %s", got)
	}
	values := url.Values{"Action": {"DescribeDomainRecords"}, "DomainName": {"example.com"}, "SignatureNonce": {"nonce"}}
	if signAli(values, "secret") != "3e3/nM9AOBn12flPqKcoRRRMFec=" {
		t.Fatal("invalid HMAC-SHA1 base64 signature")
	}
}
