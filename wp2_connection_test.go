package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWP2ConnectionServerOverridesHost(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"jpa9.help600.com;2086;0;ws;;path=/Kugou|server=jpa2.help600.com|host=kugou.com|outside_port=2086", "jpa2.help600.com"},
		{"jpa2.help600.com;2086;0;ws;;path=/Kugou|server=jpa2.help600.com|host=kugou.com|outside_port=2086", "jpa2.help600.com"},
		{"jpa9.help600.com;2086;0;ws;;path=/Kugou|host=kugou.com", "jpa9.help600.com"},
		{"node.help600.com;port=443|net=ws|server=edge.help600.com|host=other.com", "edge.help600.com"},
		{"node.help600.com;443;0;tcp;;server=edge.help600.com|relayserver=relay.help600.com|host=other.com", "relay.help600.com"},
	} {
		got, err := wp2ConnectionAddress(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("got %q %v, want %q", got, err, tc.want)
		}
	}
}
func TestDeploymentDNSUsesConnectionNotWebsocketHost(t *testing.T) {
	var names []string
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			w.Write([]byte(`{"server_type":"vless","network":"ws","server_name":"kugou.com","server_port":2086}`))
		case "/mod_mu/nodes/929/info":
			w.Write([]byte(`{"ret":1,"data":{"server":"jpa9.help600.com;2086;0;ws;;path=/Kugou|server=jpa2.help600.com|host=kugou.com|outside_port=2086"}}`))
		case "/zones":
			w.Write([]byte(`{"success":true,"result":[{"id":"z","name":"help600.com"}]}`))
		case "/zones/z/dns_records":
			if r.Method == "GET" {
				w.Write([]byte(`{"success":true,"result":[]}`))
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			names = append(names, body["name"].(string))
			if body["content"] != "104.64.213.47" {
				t.Error("wrong target IP")
			}
			w.Write([]byte(`{"success":true,"result":{"id":"a"}}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer upstream.Close()
	t.Setenv("DNS_CF_API_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	dnsTestStore(t, s)
	raw, _ := json.Marshal(DNSConfig{Zone: "help600.com", Provider: "cloudflare", Token: "cf-token", Enabled: true})
	s.saveRootPassword("dns-provider-help600.com", 0, "DNS", string(raw))
	instance := Instance{ID: 110253637, IPv4: []string{"104.64.213.47"}}
	ready, log, err := s.prepareDeploymentDNS(context.Background(), upstream.URL, "wp2-token", 929, &instance)
	if err != nil || !ready || len(names) != 1 || names[0] != "jpa2.help600.com" {
		t.Fatalf("DNS wrong target: %v %v %v", ready, err, names)
	}
	if !strings.Contains(log, "jpa2.help600.com") || !strings.Contains(log, "104.64.213.47") || strings.Contains(log, "kugou.com") {
		t.Fatalf("DNS log missing or wrong target: %s", log)
	}
	if instance.DNSDomain != "jpa2.help600.com" {
		t.Fatal("remote propagation check would use wrong address")
	}
}
