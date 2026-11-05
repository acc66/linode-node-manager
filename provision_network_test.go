package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAllPortsNetworkModes(t *testing.T) {
	t.Setenv("LINODE_TOKEN", "mock")
	for _, mode := range []string{"legacy_config_only", "linode_only", "linode_default_but_legacy_config_allowed"} {
		t.Run(mode, func(t *testing.T) {
			upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/v4/account/settings" {
					t.Error("unexpected network request")
				}
				json.NewEncoder(w).Encode(map[string]string{"interfaces_for_new_linodes": mode})
			}))
			defer upstream.Close()
			t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
			payload := map[string]any{}
			if err := testServer(upstream.Client()).openNetworkConfig(context.Background(), "legacy", payload); err != nil {
				t.Fatal(err)
			}
			if mode == "legacy_config_only" {
				if payload["firewall_id"] != -1 || payload["interface_generation"] != "legacy_config" {
					t.Fatal("legacy interface did not opt out of default firewall")
				}
			} else {
				interfaces, ok := payload["interfaces"].([]map[string]any)
				if !ok || len(interfaces) != 1 || interfaces[0]["firewall_id"] != -1 || payload["interface_generation"] != "linode" {
					t.Fatal("new interface did not opt out of default firewall")
				}
			}
		})
	}
}
