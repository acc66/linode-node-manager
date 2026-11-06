package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPChangeWorkflowKeepsOriginalAndCleansHelper(t *testing.T) {
	for _, mode := range []string{"success", "swap_rejected", "swap_timeout_but_changed", "verify_failed", "cleanup_failed"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("LINODE_TOKEN", "mock")
			t.Setenv("SSH_BOOTSTRAP_DIR", filepath.Join(t.TempDir(), "ssh"))
			oldIP, newIP := "104.64.213.47", "172.104.46.26"
			original := Instance{ID: 7, Label: "original", Region: "ap-northeast", Status: "running", IPv4: []string{oldIP}, Image: "linode/debian12"}
			helper := Instance{ID: 99, Status: "offline", Region: original.Region, IPv4: []string{newIP}}
			created, deleted, swapped, booted := 0, 0, false, false
			var requests []string
			upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				switch {
				case r.Method == "GET" && r.URL.Path == "/v4/account/settings":
					w.Write([]byte(`{"interfaces_for_new_linodes":"legacy_config_only"}`))
				case r.Method == "GET" && r.URL.Path == "/v4/linode/instances/7":
					json.NewEncoder(w).Encode(original)
				case r.Method == "POST" && r.URL.Path == "/v4/linode/instances":
					created++
					var payload map[string]any
					json.NewDecoder(r.Body).Decode(&payload)
					if payload["booted"] != false || payload["image"] != nil || payload["region"] != "ap-northeast" {
						t.Error("helper must not boot/install OS or use another region")
					}
					helper.Label = payload["label"].(string)
					json.NewEncoder(w).Encode(helper)
				case r.Method == "GET" && r.URL.Path == "/v4/linode/instances/99":
					if swapped && mode == "verify_failed" {
						w.WriteHeader(502)
						return
					}
					json.NewEncoder(w).Encode(helper)
				case r.Method == "POST" && r.URL.Path == "/v4/linode/instances/7/shutdown":
					original.Status = "offline"
					w.Write([]byte(`{}`))
				case r.Method == "POST" && r.URL.Path == "/v4/networking/ips/assign":
					var payload struct {
						Region      string `json:"region"`
						Assignments []struct {
							Address string `json:"address"`
							ID      int    `json:"linode_id"`
						} `json:"assignments"`
					}
					json.NewDecoder(r.Body).Decode(&payload)
					if payload.Region != original.Region || len(payload.Assignments) != 2 || payload.Assignments[0].Address != newIP || payload.Assignments[0].ID != 7 || payload.Assignments[1].Address != oldIP || payload.Assignments[1].ID != 99 {
						t.Error("wrong swap assignments")
					}
					if mode == "swap_rejected" {
						w.WriteHeader(400)
						return
					}
					original.IPv4 = []string{newIP}
					helper.IPv4 = []string{oldIP}
					swapped = true
					if mode == "swap_timeout_but_changed" {
						w.WriteHeader(500)
						return
					}
					w.Write([]byte(`{}`))
				case r.Method == "POST" && r.URL.Path == "/v4/linode/instances/7/boot":
					booted = true
					original.Status = "running"
					w.Write([]byte(`{}`))
				case r.Method == "DELETE" && r.URL.Path == "/v4/linode/instances/99":
					if mode == "cleanup_failed" {
						w.WriteHeader(503)
						return
					}
					deleted++
					w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected request (original must not be deleted/rebuilt): %s %s", r.Method, r.URL.Path)
				}
			}))
			defer upstream.Close()
			t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
			s := testServer(upstream.Client())
			dnsTestStore(t, s)
			op := &IPChange{Job: Job{ID: "ip-test", Kind: "ip_change", Status: "queued", InstanceID: 7, AccountID: "legacy"}, Original: original, Plan: "g6-nanode-1", HelperLabel: "lnm-ip-7-test"}
			err := s.runIPChange(context.Background(), op)
			if created != 1 {
				t.Fatalf("helper creation count %d", created)
			}
			switch mode {
			case "success", "swap_timeout_but_changed":
				if err != nil || op.Job.Status != "success" || !op.SwapVerified || !op.HelperCleaned || deleted != 1 || !booted || original.ID != 7 || publicIP(original) != newIP {
					t.Fatalf("swap failed: %v %+v", err, op.Job)
				}
			case "swap_rejected":
				if err == nil || deleted != 1 || publicIP(original) != oldIP || original.Status != "running" {
					t.Fatal("failed swap did not restore original and clean helper")
				}
			case "verify_failed":
				if err == nil || deleted != 0 || op.HelperCleaned {
					t.Fatal("unknown swap must preserve helper")
				}
			case "cleanup_failed":
				if err == nil || !op.SwapVerified || op.HelperCleaned || original.Status != "running" {
					t.Fatal("cleanup failure was hidden or original not running")
				}
			}
			restored, err := s.loadIPChange("ip-test")
			if err != nil || restored.HelperID != 99 {
				t.Fatal("helper identity not persisted")
			}
			if strings.Contains(strings.Join(requests, "\n"), "DELETE /v4/linode/instances/7\n") {
				t.Fatal("original deleted")
			}
		})
	}
}
func TestIPChangeRequiresConfirmationAndNetworkHelper(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	mutations := 0
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			mutations++
			w.WriteHeader(500)
			return
		}
		switch r.URL.Path {
		case "/v4/linode/instances/7":
			w.Write([]byte(`{"id":7,"status":"running","region":"ap-northeast","ipv4":["104.64.213.47"]}`))
		case "/v4/networking/ips/104.64.213.47":
			w.Write([]byte(`{"linode_id":7,"public":true,"reserved":false}`))
		case "/v4/linode/instances/7/configs":
			w.Write([]byte(`{"data":[{"helpers":{"network":false}}]}`))
		default:
			t.Errorf("unexpected lookup %s", r.URL.Path)
		}
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	dnsTestStore(t, s)
	h := newHandler(s)
	if w := apiRequest(h, "POST", "/api/instances/7/change-ip?account_id=legacy", `{}`); w.Code != 400 {
		t.Fatal("billing not confirmed but accepted")
	}
	w := apiRequest(h, "POST", "/api/instances/7/change-ip?account_id=legacy", `{"plan":"g6-nanode-1","expected_ip":"104.64.213.47","confirm_instance_id":7,"confirm_billing":true,"expected_hourly":0.0075}`)
	if w.Code != 409 || mutations != 0 {
		t.Fatalf("unsafe networking created helper: %d mutations=%d", w.Code, mutations)
	}
}
func TestIPChangeCleanupRejectsOriginalAndNonHelper(t *testing.T) {
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	op := &IPChange{Job: Job{ID: "ip-test", Kind: "ip_change", AccountID: "legacy"}, Original: Instance{ID: 7}, HelperID: 7}
	if err := s.cleanupIPHelper(context.Background(), op); err == nil {
		t.Fatal("cleanup accepted original ID")
	}
}

func TestIPChangeTaskSurvivesRestart(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	op := &IPChange{Job: Job{ID: "ip-persisted", Kind: "ip_change", Status: "running", AccountID: "legacy", InstanceID: 7}, Original: Instance{ID: 7}, HelperID: 99, HelperLabel: "lnm-ip-7-test"}
	if err := s.saveIPChange(op); err != nil {
		t.Fatal(err)
	}
	restarted := testServer(http.DefaultClient)
	restarted.credentials = s.credentials
	w := apiRequest(newHandler(restarted), "GET", "/api/deployments/ip-persisted", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"interrupted"`) || !strings.Contains(w.Body.String(), `"helper_id":99`) {
		t.Fatalf("lost recovery information: %d %s", w.Code, w.Body.String())
	}
}
