package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBootTuningJobReportsActualKernelResult(t *testing.T) {
	for _, result := range []string{"BBR_ENABLED: bbr", "BBR_UNSUPPORTED: no module"} {
		t.Run(result, func(t *testing.T) {
			t.Setenv("LINODE_TOKEN", "mock")
			upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"id":7,"status":"running","ipv4":["104.64.213.47"]}`))
			}))
			defer upstream.Close()
			t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
			s := testServer(upstream.Client())
			s.skipBootTuning = false
			dnsTestStore(t, s)
			s.saveRootPassword("legacy", 7, "node", "root-password")
			s.saveRootPassword("open-ports-legacy", 7, "node", "true")
			s.sshRun = func(_ context.Context, _ string, script string) (string, error) {
				if !strings.Contains(script, "tcp_congestion_control=bbr") || !strings.Contains(script, "root soft nofile 65535") {
					t.Error("missing requested persistent tuning")
				}
				if !strings.Contains(script, "ufw insert 1 allow in from any to any") || !strings.Contains(script, "UFW_ALL_PORTS_ENABLED") {
					t.Error("saved open-all-ports setting not applied during boot")
				}
				return result, nil
			}
			id := s.queueBootTuning("legacy", 7, false)
			if id == "" {
				t.Fatal("tuning job not queued")
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				s.mu.RLock()
				job := s.jobs[id]
				s.mu.RUnlock()
				if job.Status == "success" || job.Status == "partial" {
					if strings.Contains(result, "UNSUPPORTED") && job.Status != "partial" {
						t.Fatal("unsupported BBR reported as enabled")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("tuning job did not complete")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestBootInitializationOnlyAddsUFWRulesWhenEnabled(t *testing.T) {
	if strings.Contains(bootInitializationScript(false), "ufw insert 1") {
		t.Fatal("UFW allow-all rules must respect the saved instance setting")
	}
	script := bootInitializationScript(true)
	if !strings.Contains(script, "ufw status numbered") || !strings.Contains(script, "ufw insert 1 allow out from any to any") {
		t.Fatal("boot UFW setup must be idempotent and allow outbound traffic")
	}
}
