package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func createRefillDraft(t *testing.T, s *Server, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name})
	w := apiRequest(newHandler(s), "POST", "/api/refill/tasks", string(body))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		ID  string `json:"task_id"`
		URL string `json:"status_url"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || !validRefillTaskID(result.ID) || result.ID == defaultRefillTask || result.URL != taskStatusURL(result.ID) {
		t.Fatal("missing task identifier", w.Body.String())
	}
	return result.ID
}
func awaitRefillTask(t *testing.T, s *Server, id string, ready func(RefillState) bool) RefillState {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.loadRefillTask(id)
		if err == nil && ready(st) {
			rt := s.refillRuntime(id)
			if rt.mu.TryLock() {
				rt.mu.Unlock()
				return st
			}
		}

		time.Sleep(time.Millisecond * 5)
	}
	st, err := s.loadRefillTask(id)
	t.Fatalf("task %s did not reach expected state: %s (%v)", id, st.Stage, err)
	return st
}
func TestRefillTasksCreateQueryPersistAndRedact(t *testing.T) {
	s, ids := newRefillTestServer(t)
	id := createRefillDraft(t, s, "日本补机")
	st, err := s.loadRefillTask(id)
	if err != nil || st.Stage != "draft" || st.Config.Enabled {
		t.Fatal("draft unexpectedly enabled", err)
	}
	st.Config = refillTestConfig(ids)
	st.Config.Script = "script-secret"
	st.Pending = &RefillPending{Account: ids[0], ID: 99, Label: "pending-node", Password: "root-password-secret"}
	if err = s.saveRefill(&st, "independent task history"); err != nil {
		t.Fatal(err)
	}
	h := newHandler(s)
	detail := apiRequest(h, "GET", taskStatusURL(id), "")
	if detail.Code != 200 || strings.Contains(detail.Body.String(), "root-password-secret") || !strings.Contains(detail.Body.String(), "independent task history") {
		t.Fatal("detail missing or leaks password", detail.Code)
	}
	list := apiRequest(h, "GET", "/api/refill/tasks", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), id) || strings.Contains(list.Body.String(), "script-secret") || strings.Contains(list.Body.String(), "root-password-secret") {
		t.Fatal("summary leaked secrets or omitted task")
	}
	if w := apiRequest(h, "GET", "/api/refill/tasks/does-not-exist", ""); w.Code != 404 {
		t.Fatal("unknown task accepted", w.Code)
	}
	disk, err := os.ReadFile(s.credentials.file)
	if err != nil || strings.Contains(string(disk), "root-password-secret") {
		t.Fatal("task state is not encrypted")
	}
	other := testServer(http.DefaultClient)
	other.credentials, err = initAccounts(s.credentials.file, strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := other.loadRefillTask(id)
	if err != nil || restored.Pending == nil || restored.Pending.Password != "root-password-secret" || restored.TaskID != id {
		t.Fatal("task did not persist", err)
	}
	if w := apiRequest(h, "DELETE", taskStatusURL(id), "{}"); w.Code != 409 {
		t.Fatal("deleted task owning resources")
	}
	draft := createRefillDraft(t, s, "可删除草稿")
	if w := apiRequest(h, "DELETE", taskStatusURL(draft), "{}"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if _, err = s.loadRefillTask(draft); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("draft not removed")
	}
}
func TestRefillTaskClaimsAreAtomicAndDomainsExclusive(t *testing.T) {
	s, ids := newRefillTestServer(t)
	a := createRefillDraft(t, s, "A")
	b := createRefillDraft(t, s, "B")
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for _, id := range []string{a, b} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			st, _ := s.loadRefillTask(id)
			st.Pending = &RefillPending{Account: ids[0], Label: "intent"}
			if err := s.saveRefill(&st, "reserve"); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, errRefillOwned) {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("same account assigned twice", accepted.Load())
	}
	aState, _ := s.loadRefillTask(a)
	bState, _ := s.loadRefillTask(b)
	owner, other := aState, bState
	if owner.Pending == nil {
		owner, other = other, owner
	}
	available, err := s.accountAvailableForTask(other.TaskID, ids[0])
	if err != nil || available {
		t.Fatal("pending account not reserved", err)
	}
	owner.Config.Domain = "node.example.com"
	if err = s.saveRefill(&owner, ""); err != nil {
		t.Fatal(err)
	}
	other.Config.Domain = "node.example.com"
	if err = s.saveRefill(&other, ""); !errors.Is(err, errRefillOwned) {
		t.Fatal("same domain assigned twice", err)
	}
}
func TestRefillTaskQueueAndPauseAreIndependent(t *testing.T) {
	s, ids := newRefillTestServer(t)
	a := createRefillDraft(t, s, "A")
	b := createRefillDraft(t, s, "B")
	h := newHandler(s)
	for _, id := range []string{a, b} {
		st, _ := s.loadRefillTask(id)
		st.Config = refillTestConfig(ids)
		if err := s.saveRefill(&st, ""); err != nil {
			t.Fatal(err)
		}
		if w := apiRequest(h, "POST", taskStatusURL(id)+"/run", `{"confirm_billing":true}`); w.Code != 202 || !strings.Contains(w.Body.String(), id) {
			t.Fatal(w.Body.String())
		}
		if w := apiRequest(h, "POST", taskStatusURL(id)+"/run", `{"confirm_billing":true}`); w.Code != 409 {
			t.Fatal("duplicate enqueue accepted")
		}
	}
	if w := apiRequest(h, "POST", taskStatusURL(a)+"/pause", `{}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	aState, _ := s.loadRefillTask(a)
	bState, _ := s.loadRefillTask(b)
	if aState.Stage != "paused" || aState.QueuedAction != "" || bState.QueuedAction != "run" {
		t.Fatal("pause affected another task")
	}
}
func TestRefillMonitoringContinuesWhilePaidSlotBusy(t *testing.T) {
	s, ids := newRefillTestServer(t)
	a := createRefillDraft(t, s, "A")
	b := createRefillDraft(t, s, "B")
	for i, id := range []string{a, b} {
		st, _ := s.loadRefillTask(id)
		st.Config = refillTestConfig(ids)
		st.Config.Enabled = true
		st.CurrentAccount = ids[i]
		st.CurrentID = 10 + i
		if err := s.saveRefill(&st, ""); err != nil {
			t.Fatal(err)
		}
	}
	s.linodeHook = func(_ context.Context, account, method, path string, _ io.Reader) ([]byte, int, error) {
		if account != ids[1] || method != "GET" {
			t.Error("unexpected operation during monitor")
		}
		if path == "/account" {
			return []byte(`{"balance":-100,"balance_uninvoiced":0}`), 200, nil
		}
		return []byte(`{"data":[]}`), 200, nil
	}
	rt := s.refillRuntime(a)
	rt.mu.Lock()
	s.refillMu.Lock()
	s.refillTaskTick(context.Background())
	awaitRefillTask(t, s, b, func(st RefillState) bool { return !st.LastCheck.IsZero() && st.Stage == "ready" })
	s.refillMu.Unlock()
	rt.mu.Unlock()
}
func TestRefillPaidOperationsAreFIFOAndQueryable(t *testing.T) {
	s, ids := newRefillTestServer(t)
	a := createRefillDraft(t, s, "A")
	b := createRefillDraft(t, s, "B")
	probe, _ := json.Marshal(DomesticProbeConfig{Host: "203.0.113.100", Port: 22, User: "root", Password: "test-password"})
	_ = s.saveRootPassword("domestic-probe", 0, "probe", string(probe))
	for i, id := range []string{a, b} {
		st, _ := s.loadRefillTask(id)
		st.Config = refillTestConfig(ids)
		st.CurrentAccount = ids[i]
		st.CurrentID = 10 + i
		st.QueuedAction = "probe"
		st.Stage = "queued"
		st.QueuedAt = time.Now().Add(time.Duration(i-2) * time.Minute)
		if err := s.saveRefill(&st, ""); err != nil {
			t.Fatal(err)
		}
	}
	s.linodeHook = func(_ context.Context, account, method, path string, _ io.Reader) ([]byte, int, error) {
		id := 10
		ip := "192.0.2.10"
		if account == ids[1] {
			id = 11
			ip = "192.0.2.11"
		}
		body, _ := json.Marshal(Instance{ID: id, Status: "running", IPv4: []string{ip}})
		return body, 200, nil
	}
	s.refillWaitPort = func(_ context.Context, account string, id, port int) (Instance, error) {
		return s.ipInstance(context.Background(), account, id)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	var orderMu sync.Mutex
	order := []string{}
	s.sshRun = func(_ context.Context, _ string, script string) (string, error) {
		n := inFlight.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		defer inFlight.Add(-1)
		which := a
		if strings.Contains(script, "192.0.2.11") {
			which = b
		}
		orderMu.Lock()
		order = append(order, which)
		orderMu.Unlock()
		entered <- struct{}{}
		if which == a {
			<-release
		}
		return "DOMESTIC_TCP_OPEN\n", nil
	}
	s.refillTaskTick(context.Background())
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first paid operation never started")
	}
	detail := apiRequest(newHandler(s), "GET", taskStatusURL(a), "")
	if detail.Code != 200 || !strings.Contains(detail.Body.String(), `"busy":true`) {
		t.Fatal("cannot query running task")
	}
	s.refillTaskTick(context.Background())
	if peak.Load() != 1 {
		t.Fatal("paid operations ran concurrently")
	}
	close(release)
	awaitRefillTask(t, s, a, func(st RefillState) bool { return st.Stage == "ready" })
	// Wait until the first worker has released its global slot.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.refillTaskTick(context.Background())
		select {
		case <-entered:
			goto secondStarted
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("second queued task starved")
secondStarted:
	awaitRefillTask(t, s, b, func(st RefillState) bool { return st.Stage == "ready" })
	orderMu.Lock()
	defer orderMu.Unlock()
	if len(order) != 2 || order[0] != a || order[1] != b || peak.Load() != 1 {
		t.Fatal("queue order or serialization failed", order, peak.Load())
	}
}

func TestRefillIPRetryYieldsSlotToAnotherTask(t *testing.T) {
	s, ids := newRefillTestServer(t)
	a := createRefillDraft(t, s, "持续换 IP")
	b := createRefillDraft(t, s, "其他任务")
	probe, _ := json.Marshal(DomesticProbeConfig{Host: "203.0.113.100", Port: 22, User: "root", Password: "test-password"})
	_ = s.saveRootPassword("domestic-probe", 0, "probe", string(probe))
	first, _ := s.loadRefillTask(a)
	first.Config = refillTestConfig(ids)
	first.Config.BootCheck = true
	first.Pending = &RefillPending{Account: ids[0], ID: 20, Label: "candidate-node", Password: "candidate-password"}
	first.QueuedAction = "continue"
	first.QueuedAt = time.Now().Add(-2 * time.Minute)
	first.Stage = "queued"
	if err := s.saveRefill(&first, ""); err != nil {
		t.Fatal(err)
	}
	second, _ := s.loadRefillTask(b)
	second.Config = refillTestConfig(ids)
	second.CurrentAccount = ids[1]
	second.CurrentID = 30
	second.QueuedAction = "probe"
	second.QueuedAt = time.Now().Add(-time.Minute)
	second.Stage = "queued"
	if err := s.saveRefill(&second, ""); err != nil {
		t.Fatal(err)
	}
	s.refillWait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	s.linodeHook = func(_ context.Context, account, method, path string, _ io.Reader) ([]byte, int, error) {
		id := 20
		label := "candidate-node"
		ip := "192.0.2.20"
		if account == ids[1] {
			id = 30
			label = "other-node"
			ip = "192.0.2.30"
		}
		body, _ := json.Marshal(Instance{ID: id, Label: label, Status: "running", IPv4: []string{ip}})
		return body, 200, nil
	}
	s.refillWaitPort = func(ctx context.Context, account string, id, port int) (Instance, error) {
		return s.ipInstance(ctx, account, id)
	}
	s.sshRun = func(_ context.Context, host, script string) (string, error) {
		if host != "203.0.113.100" {
			t.Error("startup script ran before domestic IP passed")
		}
		if strings.Contains(script, "192.0.2.30") {
			return "DOMESTIC_TCP_OPEN\n", nil
		}
		return "DOMESTIC_TCP_CLOSED\n", nil
	}
	var attempts atomic.Int32
	s.refillReplaceIP = func(_ context.Context, _ string, instance Instance, _ int, _ string, _ bool) (Instance, *IPChange, error) {
		attempts.Add(1)
		return instance, &IPChange{}, fmt.Errorf("candidate rejected: %w", errDomesticTCPUnreachable)
	}
	s.refillTaskTick(context.Background())
	yielded := awaitRefillTask(t, s, a, func(st RefillState) bool {
		return st.Stage == "ip_retry" && st.QueuedAction == "continue" && st.NextRunAt.After(time.Now())
	})
	if yielded.Pending == nil || attempts.Load() != 1 {
		t.Fatal("retry intent was lost or busy-looped")
	}
	s.refillTaskTick(context.Background())
	awaitRefillTask(t, s, b, func(st RefillState) bool { return st.Stage == "ready" })
	if attempts.Load() != 1 {
		t.Fatal("IP retry ignored backoff and starved another task")
	}
}

func TestRefillPauseDuringSettingsDoesNotCancelFutureWork(t *testing.T) {
	s, _ := newRefillTestServer(t)
	id := createRefillDraft(t, s, "配置任务")
	rt := s.refillRuntime(id)
	rt.mu.Lock()
	response := apiRequest(newHandler(s), "POST", taskStatusURL(id)+"/pause", `{}`)
	rt.mu.Unlock()
	if response.Code != 409 {
		t.Fatal("claimed to stop a worker that was not running", response.Code)
	}
	s.refillTasksMu.Lock()
	queuedPause := rt.pauseRequested
	s.refillTasksMu.Unlock()
	if queuedPause {
		t.Fatal("pause leaked into a future operation")
	}
}
