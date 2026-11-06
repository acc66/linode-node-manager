package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPChangeDirectlyReplacesIPv4OnOriginal(t *testing.T) {
	t.Setenv("LINODE_TOKEN", "mock")
	t.Setenv("SSH_BOOTSTRAP_DIR", filepath.Join(t.TempDir(), "ssh"))
	oldIP, newIP := "104.64.213.47", "172.104.46.26"
	original := Instance{ID: 7, Label: "original", Region: "ap-northeast", Status: "running", IPv4: []string{oldIP}, Image: "linode/debian12"}
	allocated, oldReleased, boots, shutdowns := false, false, 0, 0
	var requests []string
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "GET" && r.URL.Path == "/v4/linode/instances/7":
			json.NewEncoder(w).Encode(original)
		case r.Method == "GET" && r.URL.Path == "/v4/networking/ips/"+oldIP:
			w.Write([]byte(`{"linode_id":7,"public":true,"reserved":false}`))
		case r.Method == "GET" && r.URL.Path == "/v4/linode/instances/7/configs":
			w.Write([]byte(`{"data":[{"helpers":{"network":true}}]}`))
		case r.Method == "POST" && r.URL.Path == "/v4/linode/instances/7/shutdown":
			shutdowns++
			original.Status = "offline"
			w.Write([]byte(`{}`))
		case r.Method == "POST" && r.URL.Path == "/v4/linode/instances/7/ips":
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload["type"] != "ipv4" || payload["public"] != true {
				t.Errorf("unexpected additional-IP request: %#v", payload)
			}
			allocated = true
			original.IPv4 = []string{oldIP, newIP}
			w.Write([]byte(`{"address":"172.104.46.26","linode_id":7,"public":true,"region":"ap-northeast"}`))
		case r.Method == "POST" && r.URL.Path == "/v4/linode/instances/7/boot":
			boots++
			original.Status = "running"
			w.Write([]byte(`{}`))
		case r.Method == "DELETE" && r.URL.Path == "/v4/linode/instances/7/ips/"+oldIP:
			if !allocated {
				t.Error("old IP released before a new IP was allocated")
			}
			oldReleased = true
			original.IPv4 = []string{newIP}
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected Linode request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	dnsTestStore(t, s)
	if err := s.saveRootPassword("legacy", 7, "original", "secret-root-password"); err != nil {
		t.Fatal(err)
	}
	s.sshRun = func(_ context.Context, ip, _ string) (string, error) {
		if ip != newIP {
			t.Errorf("SSH verification used %s, want new IP", ip)
		}
		return "SSH ok", nil
	}
	op := &IPChange{Job: Job{ID: "ip-test", Kind: "ip_change", Status: "queued", InstanceID: 7, AccountID: "legacy", OldIP: oldIP}, Original: original}
	if err := s.runIPChange(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if !allocated || !oldReleased || boots != 2 || shutdowns != 2 || original.Status != "running" || publicIP(original) != newIP || op.Job.Status != "success" || !op.SwapVerified {
		t.Fatalf("direct IP replacement failed: allocated=%v released=%v boots=%d shutdowns=%d original=%+v job=%+v", allocated, oldReleased, boots, shutdowns, original, op.Job)
	}
	for _, request := range requests {
		if strings.Contains(request, "POST /v4/linode/instances\n") {
			t.Fatal("direct IP flow created a temporary Linode")
		}
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
