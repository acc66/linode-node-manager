package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestBackendLogsReadOnlyAndRedacted(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	t.Setenv("WP2_API_TOKEN", "private-log-token")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v4/linode/instances/7" {
			t.Error("unexpected mutating request")
		}
		w.Write([]byte(`{"id":7,"status":"running","ipv4":["104.64.213.47"]}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	s.sshRun = func(_ context.Context, ip, script string) (string, error) {
		if ip != "104.64.213.47" || !strings.Contains(script, "journalctl") {
			t.Error("wrong log target")
		}
		return "Warning: known host added\n" + `{"service":"active","log":"ready private-log-token"}` + "\n", nil
	}
	w := apiRequest(newHandler(s), "GET", "/api/instances/7/backend/logs?account_id=legacy", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "active") || strings.Contains(w.Body.String(), "private-log-token") {
		t.Fatalf("logs: %d %s", w.Code, w.Body.String())
	}
}
