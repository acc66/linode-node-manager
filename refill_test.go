package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newRefillTestServer(t *testing.T) (*Server, []string) {
	t.Helper()
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	s := testServer(http.DefaultClient)
	var err error
	s.accounts, err = initAccounts(filepath.Join(t.TempDir(), "accounts.enc"), strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	s.credentials, err = initAccounts(filepath.Join(t.TempDir(), "credentials.enc"), strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for i, name := range []string{"first", "second"} {
		a, err := s.accounts.add(name, strings.Repeat(name, 15))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
		if err := s.saveProxyConfig(a.ID, "http://user:secret@"+name+".example:8080"); err != nil {
			t.Fatal(i, err)
		}
	}
	s.egressLookup = func(_ context.Context, raw string) (string, error) {
		if strings.Contains(raw, "first.example") {
			return "203.0.113.10", nil
		}
		return "203.0.113.20", nil
	}
	return s, ids
}
func refillTestConfig(ids []string) RefillConfig {
	c := defaultRefillConfig()
	c.Accounts = ids
	c.Region = "us-east"
	c.Type = "g6-nanode-1"
	c.BootCheck = false
	c.Script = "echo initialized"
	return c
}
func TestRefillCreditAccounting(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, body string
		want       float64
		bad        bool
	}{
		{"monthly cap", `{"balance":0,"balance_uninvoiced":5,"active_promotions":[{"service_type":"linode","credit_remaining":"80","this_month_credit_remaining":"10","expire_dt":"2027-01-01T00:00:00"}]}`, 5, false},
		{"expired", `{"balance":-20,"balance_uninvoiced":3,"active_promotions":[{"service_type":"all","credit_remaining":"100","this_month_credit_remaining":"100","expire_dt":"2020-01-01T00:00:00"}]}`, 17, false},
		{"unrelated promo", `{"balance":0,"balance_uninvoiced":0,"active_promotions":[{"service_type":"objectstorage","credit_remaining":"100","this_month_credit_remaining":"100"}]}`, 0, false},
		{"debt is not credit", `{"balance":100,"balance_uninvoiced":10}`, 0, false},
		{"missing", `{}`, 0, true},
		{"null", `{"balance":null,"balance_uninvoiced":0}`, 0, true},
		{"bad amount", `{"balance":0,"balance_uninvoiced":0,"active_promotions":[{"service_type":"all","credit_remaining":"NaN","this_month_credit_remaining":"100"}]}`, 0, true},
		{"bad expiry", `{"balance":0,"balance_uninvoiced":0,"active_promotions":[{"service_type":"all","credit_remaining":"100","this_month_credit_remaining":"100","expire_dt":"wrong"}]}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := refillCredit([]byte(tc.body), now)
			if (err != nil) != tc.bad || value != tc.want {
				t.Fatalf("credit=%v err=%v", value, err)
			}
		})
	}
}
func TestAccountEgressIsolationPersistenceAndNoFallback(t *testing.T) {
	s, ids := newRefillTestServer(t)
	if _, err := s.verifyAccountEgress(context.Background(), ids[0]); err != nil {
		t.Fatal(err)
	}
	s.egressLookup = func(context.Context, string) (string, error) { return "203.0.113.10", nil }
	if _, err := s.verifyAccountEgress(context.Background(), ids[1]); err == nil {
		t.Fatal("shared IP accepted through different proxies")
	}
	var calls atomic.Int32
	s.linodeHook = func(context.Context, string, string, string, io.Reader) ([]byte, int, error) {
		calls.Add(1)
		return []byte(`{}`), 200, nil
	}
	if err := s.saveRootPassword("account-isolation", 0, "isolation", "true"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.linodeFor(context.Background(), ids[1], "GET", "/account", nil); err == nil || calls.Load() != 0 {
		t.Fatal("shared IP reached Linode")
	}
	s.egressLookup = func(context.Context, string) (string, error) { return "", errors.New("proxy offline") }
	if _, _, err := s.linodeFor(context.Background(), ids[0], "GET", "/account", nil); err == nil || calls.Load() != 0 {
		t.Fatal("failed lookup fell back")
	}
	loaded, err := initAccounts(s.credentials.file, strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := loaded.token("account-egress-" + ids[0] + "/0")
	if !ok || !strings.Contains(raw, "203.0.113.10") || strings.Contains(raw, "secret") {
		t.Fatal("history missing or contains proxy password")
	}
	w := apiRequest(newHandler(s), "GET", "/api/account-pool", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal(w.Body.String())
	}
}
func TestAccountEgressConcurrentOwnership(t *testing.T) {
	s, ids := newRefillTestServer(t)
	s.egressLookup = func(context.Context, string) (string, error) { return "203.0.113.55", nil }
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, err := s.verifyAccountEgress(context.Background(), id); err == nil {
				accepted.Add(1)
			}
		}(id)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("same IP accepted by %d accounts", accepted.Load())
	}
}
func TestRefillAuthTriggeredHandoffAndUnknownCreate(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(strconvBool(unknown), func(t *testing.T) {
			s, ids := newRefillTestServer(t)
			st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, CurrentIP: "192.0.2.10", Cursor: 1, Stage: "ready"}
			creates, scriptRuns, shutdowns := 0, 0, 0
			newLabel := ""
			st.Config.OldPolicy = "shutdown"
			s.linodeHook = func(ctx context.Context, account, method, path string, body io.Reader) ([]byte, int, error) {
				if strict, _ := ctx.Value(isolationContextKey{}).(bool); !strict {
					t.Error("refill request lost strict isolation")
				}
				switch {
				case method == "GET" && path == "/linode/instances/10":
					return []byte(`{"id":10,"region":"us-east","status":"running","ipv4":["192.0.2.10"]}`), 200, nil
				case path == "/account":
					if account == ids[0] {
						return []byte(`{"errors":[{"reason":"Invalid Token"}]}`), 401, nil
					}
					return []byte(`{"balance":-100,"balance_uninvoiced":0}`), 200, nil
				case strings.Contains(path, "/transfer"):
					t.Error("credit-only switching queried transfer pool")
					return nil, 500, nil
				case method == "POST" && path == "/linode/instances":
					creates++
					if account != ids[1] {
						t.Error("wrong target account")
					}
					var payload map[string]any
					if json.NewDecoder(body).Decode(&payload) != nil {
						t.Fatal("bad payload")
					}
					newLabel = payload["label"].(string)
					if unknown {
						return nil, 0, errors.New("timeout")
					}
					encoded, _ := json.Marshal(Instance{ID: 20, Label: newLabel, Status: "running", IPv4: []string{"192.0.2.20"}, Region: "us-east"})
					return encoded, 201, nil
				case strings.HasPrefix(path, "/linode/instances?"):
					encoded, _ := json.Marshal(map[string]any{"data": []Instance{{ID: 20, Label: newLabel, Region: "us-east", Status: "running", IPv4: []string{"192.0.2.20"}}}, "pages": 1})
					return encoded, 200, nil
				case path == "/linode/instances/20":
					encoded, _ := json.Marshal(Instance{ID: 20, Label: newLabel, Status: "running", IPv4: []string{"192.0.2.20"}, Region: "us-east"})
					return encoded, 200, nil
				case method == "POST" && path == "/linode/instances/10/shutdown":
					shutdowns++
					if scriptRuns != 1 {
						t.Error("old stopped before deployment")
					}
					return []byte(`{}`), 200, nil
				default:
					t.Errorf("unexpected %s %s", method, path)
					return nil, 500, nil
				}
			}
			s.sshRun = func(_ context.Context, _ string, script string) (string, error) {
				if strings.Contains(script, "echo initialized") {
					scriptRuns++
				}
				return "", nil
			}
			s.refillWaitPort = func(ctx context.Context, account string, id, port int) (Instance, error) {
				if scriptRuns != 1 {
					t.Error("health check before script")
				}
				return s.ipInstance(ctx, account, id)
			}
			err := s.runRefill(context.Background(), &st, false)
			if unknown {
				if err == nil || st.Pending == nil || st.Pending.ID != 0 || creates != 1 || shutdowns != 0 {
					t.Fatal("unknown create not retained", err)
				}
				if err := s.runRefill(context.Background(), &st, false); err == nil || creates != 1 {
					t.Fatal("unknown creation repeated")
				}
				saved, err := s.loadRefill()
				if err != nil || saved.Pending == nil || saved.Pending.Password == "" {
					t.Fatal("intent not durable", err)
				}
				w := apiRequest(newHandler(s), "GET", "/api/refill", "")
				if w.Code != 200 || strings.Contains(w.Body.String(), saved.Pending.Password) {
					t.Fatal("pending password exposed")
				}
				if err := s.runRefill(context.Background(), &saved, true); err != nil || creates != 1 || saved.CurrentID != 20 {
					t.Fatal("recovery repeated create or failed", err, creates)
				}

			} else {
				if err != nil || st.CurrentID != 20 || st.CurrentAccount != ids[1] || st.Pending != nil || scriptRuns != 1 || shutdowns != 1 {
					t.Fatal("handoff failed", st, err)
				}
				if len(st.Retired) != 1 || !st.Retired[0].ShutdownRequested {
					t.Fatal("retired instance not retained")
				}
				if err := s.runRefill(context.Background(), &st, false); err != nil || creates != 1 {
					t.Fatal("healthy account created twice", err)
				}
			}
		})
	}
}
func strconvBool(v bool) string {
	if v {
		return "unknown-create"
	}
	return "successful-handoff"
}
func TestRefillAuthValidationAndConflict(t *testing.T) {
	s, ids := newRefillTestServer(t)
	h := newHandler(s)
	req := httptest.NewRequest("GET", "/refill", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 303 && w.Code != 302 {
		t.Fatal("refill is public")
	}
	w = apiRequest(h, "GET", "/refill", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "账户池") {
		t.Fatal("page missing")
	}
	config := refillTestConfig(ids)
	config.Accounts = append(config.Accounts, ids[0])
	if s.validateRefill(&config) == nil {
		t.Fatal("duplicate account accepted")
	}
	if w = apiRequest(h, "POST", "/api/refill/run", `{}`); w.Code != 400 {
		t.Fatal("billing confirmation missing")
	}
	s.refillMu.Lock()
	if w = apiRequest(h, "POST", "/api/refill/run", `{"confirm_billing":true}`); w.Code != 409 {
		t.Fatal("concurrent run accepted")
	}
	if w = apiRequest(h, "DELETE", "/api/accounts/"+ids[0], "{}"); w.Code != 409 {
		t.Fatal("account deleted during refill")
	}
	s.refillMu.Unlock()
}
func TestRefillRestartNeverReplaysMutation(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), Stage: "script", Pending: &RefillPending{Account: ids[0], Label: "node", ID: 20, Password: "test-password"}}
	st.Config.Enabled = true
	if err := s.saveRefill(&st, ""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.refillScheduler(ctx)
	saved, err := s.loadRefill()
	if err != nil || saved.Config.Enabled || saved.Stage != "interrupted" || saved.Pending == nil {
		t.Fatal("restart replay not prevented", saved, err)
	}
}

func TestRefillScriptFailurePreservesOldInstance(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, Pending: &RefillPending{Account: ids[1], ID: 20, Label: "candidate", Password: "strong-test-password"}}
	writes := 0
	s.linodeHook = func(_ context.Context, _ string, method, path string, _ io.Reader) ([]byte, int, error) {
		if method != "GET" {
			writes++
			return []byte(`{}`), 200, nil
		}
		switch path {
		case "/linode/instances/20":
			return []byte(`{"id":20,"label":"candidate","region":"us-east","status":"running","ipv4":["192.0.2.20"]}`), 200, nil
		case "/regions/us-east":
			return []byte(`{"id":"us-east","site_type":"core"}`), 200, nil
		case "/account":
			return []byte(`{"balance":-100,"balance_uninvoiced":0}`), 200, nil
		case "/account/transfer":
			return []byte(`{"used":0,"quota":1000}`), 200, nil
		}
		return nil, 500, errors.New("unexpected request")
	}
	scriptRuns := 0
	s.sshRun = func(_ context.Context, _ string, script string) (string, error) {
		if strings.Contains(script, "echo initialized") {
			scriptRuns++
			return "secret-script-output", errors.New("secret failure")
		}
		return "", nil
	}
	err := s.finishRefill(refillContext(context.Background()), &st)
	if err == nil || strings.Contains(err.Error(), "secret") || st.CurrentID != 10 || st.Pending == nil || st.Pending.ID != 20 || writes != 0 || scriptRuns != 1 {
		t.Fatalf("script failure did not preserve old instance: %v", err)
	}
}
func TestRefillProbeFailureIsNotUnreachable(t *testing.T) {
	s, ids := newRefillTestServer(t)
	config := DomesticProbeConfig{Host: "203.0.113.100", Port: 22, User: "root", Password: "test-password"}
	raw, _ := json.Marshal(config)
	if err := s.saveRootPassword("domestic-probe", 0, "probe", string(raw)); err != nil {
		t.Fatal(err)
	}
	s.refillWaitPort = func(context.Context, string, int, int) (Instance, error) {
		return Instance{ID: 10, IPv4: []string{"192.0.2.10"}}, nil
	}
	calls := 0
	s.sshRun = func(context.Context, string, string) (string, error) {
		calls++
		return "", errors.New("probe host offline")
	}
	_, err := s.checkRefillChina(context.Background(), ids[0], 10, 22)
	if err == nil || errors.Is(err, errDomesticTCPUnreachable) || calls != 1 {
		t.Fatal("probe host failure misclassified", err, calls)
	}
}

func TestRefillCreditIgnoresLegacyTrafficLimits(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, Stage: "ready"}
	st.Config.TransferPercent = -1
	st.Config.ReserveGB = 100000
	st.Config.StopPercent = 1
	s.linodeHook = func(_ context.Context, _ string, method, path string, _ io.Reader) ([]byte, int, error) {
		if method != "GET" {
			t.Fatal("healthy account mutated")
		}
		if path == "/linode/instances?page_size=25" {
			return []byte(`{"data":[]}`), 200, nil
		}
		if path != "/account" {
			t.Fatal("unexpected read", path)
		}
		return []byte(`{"balance":-99.5,"balance_uninvoiced":0}`), 200, nil
	}
	if err := s.runRefill(context.Background(), &st, false); err != nil {
		t.Fatal(err)
	}
	if st.Stage != "ready" || st.CurrentID != 10 || st.CurrentCredit == nil || *st.CurrentCredit != 99.5 {
		t.Fatal("positive credit incorrectly triggered replacement")
	}
	if st.Config.TransferPercent != 0 || st.Config.ReserveGB != 0 || st.Config.StopPercent != 0 {
		t.Fatal("legacy traffic triggers not cleared")
	}
}
func TestRefillBootRunsScriptAfterIPCheck(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10}
	st.Config.BootCheck = true
	cfg, _ := json.Marshal(DomesticProbeConfig{Host: "203.0.113.100", Port: 22, User: "root", Password: "test-password"})
	if err := s.saveRootPassword("domestic-probe", 0, "probe", string(cfg)); err != nil {
		t.Fatal(err)
	}
	checked, scriptRan := false, false
	instance := Instance{ID: 10, Label: "running-node", Status: "running", IPv4: []string{"192.0.2.10"}}
	s.linodeHook = func(_ context.Context, _ string, method, path string, _ io.Reader) ([]byte, int, error) {
		if method != "GET" || path != "/linode/instances/10" {
			t.Fatal("unexpected boot request", method, path)
		}
		b, _ := json.Marshal(instance)
		return b, 200, nil
	}
	s.refillWaitPort = func(context.Context, string, int, int) (Instance, error) { return instance, nil }
	s.sshRun = func(_ context.Context, host, script string) (string, error) {
		if host == "203.0.113.100" {
			if scriptRan {
				t.Fatal("boot script ran before initial IP check")
			}
			checked = true
			return "DOMESTIC_TCP_OPEN\n", nil
		}
		if strings.Contains(script, "echo initialized") {
			if !checked {
				t.Fatal("script ran before IP check")
			}
			scriptRan = true
		}
		return "", nil
	}
	if err := s.refillInstanceAction(refillContext(context.Background()), &st, "boot"); err != nil || !checked || !scriptRan {
		t.Fatal("boot pipeline incomplete", err)
	}
}
func TestRefillLegacyConfigMigratesToAPIMonitor(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids)}
	st.Config.Trigger = ""
	st.Config.CreditFloor = 99.5
	st.Config.TransferPercent = 90
	st.Config.StopPercent = 98
	raw, _ := json.Marshal(st)
	var legacy map[string]any
	_ = json.Unmarshal(raw, &legacy)
	delete(legacy["config"].(map[string]any), "trigger")
	raw, _ = json.Marshal(legacy)
	if err := s.saveRootPassword("refill-state", 0, "legacy", string(raw)); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.loadRefill()
	if err != nil || loaded.Config.CreditFloor != 0 || loaded.Config.Trigger != "api" || loaded.Config.StopPercent != 0 || loaded.Config.TransferPercent != 0 {
		t.Fatal("old traffic config remained active", err)
	}
}

func TestRefillAPICheckDistinguishesProviderErrors(t *testing.T) {
	for _, tc := range []struct {
		status     int
		body, kind string
	}{
		{401, `{"errors":[{"reason":"Invalid Token"}]}`, "auth_error"},
		{403, `{"errors":[{"reason":"Not authorized"}]}`, "permission_error"},
		{403, `<html>Proxy access denied</html>`, "invalid_response"},
		{429, `{}`, "rate_limited"}, {503, `{}`, "server_error"},
		{200, `{}`, "invalid_response"},
	} {
		s, ids := newRefillTestServer(t)
		s.linodeHook = func(context.Context, string, string, string, io.Reader) ([]byte, int, error) {
			return []byte(tc.body), tc.status, nil
		}
		got := s.checkRefillAPI(refillContext(context.Background()), ids[0])
		if got.Kind != tc.kind {
			t.Fatalf("HTTP %d => %s, want %s", tc.status, got.Kind, tc.kind)
		}
	}
}
func TestRefillLowCreditOnlyAlertsAndNeverChecksOldTCP(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, Cursor: 1}
	st.Config.CreditFloor = 1
	s.refillWaitPort = func(context.Context, string, int, int) (Instance, error) {
		t.Fatal("old TCP must not trigger API failover")
		return Instance{}, nil
	}
	s.linodeHook = func(_ context.Context, account, method, path string, _ io.Reader) ([]byte, int, error) {
		if account != ids[0] || method != "GET" {
			t.Fatal("healthy API triggered account switch")
		}
		if path == "/account" {
			return []byte(`{"balance":0,"balance_uninvoiced":0}`), 200, nil
		}
		return []byte(`{"data":[]}`), 200, nil
	}
	for i := 0; i < 2; i++ {
		if err := s.runRefill(context.Background(), &st, false); err != nil {
			t.Fatal(err)
		}
	}
	if st.CurrentID != 10 || !st.CreditAlerted || st.Pending != nil {
		t.Fatal("zero credit switched healthy account")
	}
	count := 0
	for _, event := range st.History {
		if strings.Contains(event.Message, "已到提醒阈值") {
			count++
		}
	}
	if count != 1 {
		t.Fatal("low credit warning repeated", count)
	}
}
func TestRefillUnreachableUsesSpacedPersistentSamplesAndPreflightsCandidate(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, Cursor: 1}
	candidateChecks, creates := 0, 0
	s.refillWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	s.linodeHook = func(_ context.Context, account, method, path string, _ io.Reader) ([]byte, int, error) {
		if method == "POST" {
			creates++
			t.Fatal("unhealthy candidate created a server")
		}
		if account == ids[1] {
			candidateChecks++
			return []byte(`{}`), 503, nil
		}
		return nil, 0, errors.New("connection timeout")
	}
	if err := s.runRefill(context.Background(), &st, false); err != nil || st.APIFailures != 1 || candidateChecks != 0 {
		t.Fatal(st.APIFailures, err)
	}
	if err := s.runRefill(context.Background(), &st, false); err != nil || st.APIFailures != 1 {
		t.Fatal("refresh manufactured failures", err)
	}
	for i := 0; i < 2; i++ {
		st.LastAPIFailure = time.Now().Add(-2 * time.Minute)
		if err := s.runRefill(context.Background(), &st, false); err != nil {
			t.Fatal(err)
		}
	}
	if st.APIFailures != 3 || candidateChecks != 1 || creates != 0 || st.Cursor != 1 || st.Stage != "api_wait" {
		t.Fatal("candidate preflight skipped or consumed queue", candidateChecks, st.Cursor, st.Stage)
	}
	saved, err := s.loadRefill()
	if err != nil || saved.APIFailures != 3 {
		t.Fatal("failure count not persistent", err)
	}
}
func TestRefillRecoveryResetsAPIFailures(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, APIFailures: 2, LastAPIFailure: time.Now()}
	s.linodeHook = func(_ context.Context, _ string, _ string, path string, _ io.Reader) ([]byte, int, error) {
		if path == "/account" {
			return []byte(`{"balance":-1,"balance_uninvoiced":0}`), 200, nil
		}
		return []byte(`{"data":[]}`), 200, nil
	}
	if err := s.runRefill(context.Background(), &st, false); err != nil || st.APIFailures != 0 || !st.LastAPIFailure.IsZero() {
		t.Fatal("recovery did not reset streak", err)
	}
}
func TestRefillUnlimitedIPRetriesUntilDomesticCheckPasses(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids)}
	cfg, _ := json.Marshal(DomesticProbeConfig{Host: "203.0.113.100", Port: 22, User: "root", Password: "test-password"})
	if err := s.saveRootPassword("domestic-probe", 0, "probe", string(cfg)); err != nil {
		t.Fatal(err)
	}
	s.refillWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	instance := Instance{ID: 20, Label: "test-node", Status: "running", IPv4: []string{"192.0.2.20"}}
	attempts := 0
	s.refillWaitPort = func(context.Context, string, int, int) (Instance, error) { return instance, nil }
	s.sshRun = func(context.Context, string, string) (string, error) {
		if attempts < 5 {
			return "DOMESTIC_TCP_CLOSED\n", nil
		}
		return "DOMESTIC_TCP_OPEN\n", nil
	}
	s.linodeHook = func(context.Context, string, string, string, io.Reader) ([]byte, int, error) {
		b, _ := json.Marshal(instance)
		return b, 200, nil
	}
	s.refillReplaceIP = func(context.Context, string, Instance, int, string, bool) (Instance, *IPChange, error) {
		attempts++
		if attempts < 5 {
			return instance, &IPChange{}, fmt.Errorf("candidate rejected: %w", errDomesticTCPUnreachable)
		}
		return instance, &IPChange{}, nil
	}
	_, err := s.ensureRefillIP(refillContext(context.Background()), &st, ids[1], instance, 22)
	if err != nil || attempts != 5 || st.IPAttempts != 5 {
		t.Fatal("IP retry capped or failed", attempts, err)
	}
}
func TestRefillIPRetryStopsOnUnknownOutcomeAndCanBePaused(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids)}
	cfg, _ := json.Marshal(DomesticProbeConfig{Host: "203.0.113.100", Port: 22, User: "root", Password: "test-password"})
	_ = s.saveRootPassword("domestic-probe", 0, "probe", string(cfg))
	s.refillWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	instance := Instance{ID: 20, Status: "running", IPv4: []string{"192.0.2.20"}}
	s.refillWaitPort = func(context.Context, string, int, int) (Instance, error) { return instance, nil }
	s.sshRun = func(context.Context, string, string) (string, error) { return "DOMESTIC_TCP_CLOSED\n", nil }
	calls := 0
	s.refillReplaceIP = func(context.Context, string, Instance, int, string, bool) (Instance, *IPChange, error) {
		calls++
		return instance, nil, errors.New("allocation result unknown")
	}
	if _, err := s.ensureRefillIP(context.Background(), &st, ids[1], instance, 22); err == nil || calls != 1 {
		t.Fatal("unknown IP allocation retried", err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.refillCancel = cancel
	s.mu.Unlock()
	s.refillMu.Lock()
	response := apiRequest(newHandler(s), "POST", "/api/refill/pause", `{}`)
	s.refillMu.Unlock()
	if response.Code != 202 || ctx.Err() == nil {
		t.Fatal("running workflow cannot be stopped", response.Code)
	}
}

func TestRefillWritePermissionCheckedAtRealCreateBeforeSkipping(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids)}
	order := []string{}
	label := ""
	s.linodeHook = func(_ context.Context, account, method, path string, body io.Reader) ([]byte, int, error) {
		order = append(order, account+" "+method+" "+path)
		if method == "GET" && path == "/account" {
			return []byte(`{"balance":-100,"balance_uninvoiced":0}`), 200, nil
		}
		if method == "GET" && strings.HasPrefix(path, "/linode/instances?") {
			return []byte(`{"data":[]}`), 200, nil
		}
		if method == "POST" && path == "/linode/instances" {
			if account == ids[0] {
				return []byte(`{"errors":[{"reason":"Not authorized"}]}`), 403, nil
			}
			var payload struct {
				Label string `json:"label"`
			}
			_ = json.NewDecoder(body).Decode(&payload)
			label = payload.Label
			b, _ := json.Marshal(Instance{ID: 20, Label: label, Status: "running", IPv4: []string{"192.0.2.20"}})
			return b, 201, nil
		}
		if method == "GET" && path == "/linode/instances/20" {
			b, _ := json.Marshal(Instance{ID: 20, Label: label, Status: "running", IPv4: []string{"192.0.2.20"}})
			return b, 200, nil
		}
		t.Fatal("unexpected request", method, path)
		return nil, 500, nil
	}
	s.sshRun = func(context.Context, string, string) (string, error) { return "", nil }
	s.refillWaitPort = func(ctx context.Context, a string, id, port int) (Instance, error) { return s.ipInstance(ctx, a, id) }
	if err := s.runRefill(context.Background(), &st, false); err != nil {
		t.Fatal(err)
	}
	if st.CurrentAccount != ids[1] || st.CurrentID != 20 || st.APIChecks[ids[0]].Kind != "permission_error" {
		t.Fatal("write-permission rejection not handled")
	}
	for _, account := range ids {
		firstList, firstCreate := -1, -1
		for i, step := range order {
			if step == account+" GET /linode/instances?page_size=25" && firstList < 0 {
				firstList = i
			}
			if step == account+" POST /linode/instances" && firstCreate < 0 {
				firstCreate = i
			}
		}
		if firstList < 0 || firstCreate <= firstList {
			t.Fatal("created before candidate preflight", order)
		}
	}
}
func TestRefillProxyFailureNeverRotatesAccount(t *testing.T) {
	s, ids := newRefillTestServer(t)
	st := RefillState{Config: refillTestConfig(ids), CurrentAccount: ids[0], CurrentID: 10, APIFailures: 2}
	s.egressLookup = func(context.Context, string) (string, error) { return "", errors.New("proxy unavailable") }
	s.linodeHook = func(context.Context, string, string, string, io.Reader) ([]byte, int, error) {
		t.Fatal("Linode contacted despite failed proxy")
		return nil, 500, nil
	}
	if err := s.runRefill(context.Background(), &st, false); err == nil || st.APIFailures != 0 || st.Pending != nil {
		t.Fatal("proxy error rotated account", err)
	}
}
