package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testServer(client *http.Client) *Server {
	return &Server{skipBootTuning: true, client: client, status: map[int]Snapshot{}, jobs: map[string]Job{}}
}

func apiRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ci-admin")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestMockLinodePowerAPI(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock-linode-token")
	var calls atomic.Int32
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mock-linode-token" {
			t.Errorf("wrong upstream authorization %q", got)
		}
		if r.Method != "POST" {
			t.Errorf("method %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/v4/linode/instances/77/") {
			t.Errorf("path %s", r.URL.Path)
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mock":true}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	h := newHandler(testServer(upstream.Client()))
	for _, action := range []string{"boot", "shutdown", "reboot"} {
		w := apiRequest(h, "POST", "/api/instances/77/"+action, `{}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"mock":true`) {
			t.Errorf("%s got %d %s", action, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/instances/0/boot", "/api/instances/77/delete", "/api/instances/not-a-number/reboot"} {
		if w := apiRequest(h, "POST", path, `{}`); w.Code != 400 {
			t.Errorf("expected invalid path %s to be 400, got %d", path, w.Code)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("mock Linode called %d times; want 3", calls.Load())
	}
	req := httptest.NewRequest("POST", "/api/instances/77/boot", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("unauthenticated power request returned %d", w.Code)
	}
}

func TestMockLinodeInstanceListing(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v4/linode/instances" {
			t.Errorf("bad path %s", r.URL.Path)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(`{"pages":2,"data":[{"id":1,"label":"one","status":"running","ipv4":["8.8.8.8"]}]}`))
		case "2":
			_, _ = w.Write([]byte(`{"pages":2,"data":[{"id":2,"label":"two","status":"offline","ipv4":[]}]}`))
		default:
			t.Errorf("unexpected page %s", r.URL.RawQuery)
		}
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	w := apiRequest(newHandler(testServer(upstream.Client())), "GET", "/api/instances", "")
	if w.Code != 200 {
		t.Fatalf("listing %d %s", w.Code, w.Body.String())
	}
	var data struct {
		Instances []Instance `json:"instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || len(data.Instances) != 2 {
		t.Fatalf("unexpected list: %+v %v", data, err)
	}
}

func TestMockWP2NodesAndDropdownData(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("WP2_API_TOKEN", "mock-wp2-secret")
	t.Setenv("WP2_NODES_PATH", "/mod_mu/nodes")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mod_mu/nodes" || r.URL.Query().Get("key") != "mock-wp2-secret" {
			t.Errorf("bad wp2 request %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"ret":1,"data":[{"id":13,"name":"测试节点","sort":11,"passwd":"must-not-leak","server":"secret-url"},{"id":14,"name":"第二节点","sort":12}]}`))
	}))
	defer upstream.Close()
	t.Setenv("WP2_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	h := newHandler(s)
	w := apiRequest(h, "GET", "/api/wp2/nodes", "")
	if w.Code != 200 {
		t.Fatalf("wp2 nodes %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "must-not-leak") || strings.Contains(w.Body.String(), "secret-url") || strings.Contains(w.Body.String(), "mock-wp2-secret") {
		t.Fatal("WP2 credential or node secret leaked to browser")
	}
	var d struct {
		Nodes []struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			Status string `json:"node_status"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || len(d.Nodes) != 2 {
		t.Fatalf("wp2 decode: %s %v", w.Body.String(), err)
	}
	if d.Nodes[0].ID != 13 || d.Nodes[1].ID != 14 || d.Nodes[0].Status != "unknown" {
		t.Fatalf("wrong dropdown node information: %+v", d.Nodes)
	}
	page := apiRequest(h, "GET", "/", "")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `id="node" multiple`) || !strings.Contains(page.Body.String(), "select.appendChild(option)") || !strings.Contains(page.Body.String(), `id="nodefilter"`) {
		t.Fatal("HTML dropdown wiring missing")
	}
}

func TestMockInstallTaskAndRedaction(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	t.Setenv("WP2_API_TOKEN", "mock-install-secret")
	t.Setenv("WP2_BASE_URL", "https://wp2.invalid")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v4/linode/instances/33" {
			t.Errorf("unexpected Linode lookup %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":33,"label":"mock","status":"running","ipv4":["8.8.8.8"]}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	scripted := make(chan string, 1)
	s.sshRun = func(_ context.Context, ip, script string) (string, error) {
		if ip != "8.8.8.8" {
			return "", errors.New("unexpected mock ip")
		}
		scripted <- script
		return "installer log: mock-install-secret", nil
	}
	h := newHandler(s)
	for _, body := range []string{`{}`, `{"instance_id":33,"mode":"machine","target_id":19}`, `{"instance_id":0,"mode":"node","target_id":19}`} {
		w := apiRequest(h, "POST", "/api/deployments/install", body)
		if w.Code != 400 {
			t.Fatalf("invalid install should be 400, got %d", w.Code)
		}
	}
	w := apiRequest(h, "POST", "/api/deployments/install", `{"instance_id":33,"mode":"node","target_id":19}`)
	if w.Code != 202 {
		t.Fatalf("install should queue: %d %s", w.Code, w.Body.String())
	}
	var queued struct {
		ID string `json:"job_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &queued); err != nil || queued.ID == "" {
		t.Fatalf("bad job id: %v", err)
	}
	select {
	case script := <-scripted:
		if !strings.Contains(script, "XN_AUTODEPLOY") || !strings.Contains(script, "CertMagic") || !strings.Contains(script, "sha256") {
			t.Fatalf("automatic deployment script malformed")
		}
		if strings.Contains(script, "tcp_congestion_control=bbr") || strings.Contains(script, "NOFILE_CONFIGURED") || strings.Contains(script, "ufw insert 1") {
			t.Fatal("backend install must not repeat boot-time system tuning")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("mock SSH runner not invoked")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := apiRequest(h, "GET", "/api/deployments/"+queued.ID, "")
		if got.Code != 200 {
			t.Fatalf("job lookup: %d %s", got.Code, got.Body.String())
		}
		var job Job
		if err := json.Unmarshal(got.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		if job.Status == "success" {
			if strings.Contains(job.Log, "mock-install-secret") || !strings.Contains(job.Log, "[REDACTED]") {
				t.Fatalf("job log contains credential: %q", job.Log)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not complete, status=%s", job.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := apiRequest(h, "GET", "/api/deployments/absent", ""); w.Code != 404 {
		t.Errorf("missing task returns %d", w.Code)
	}
}

func TestMonitorMetricsProbe(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	out, err := exec.Command("bash", "-c", probeScript).CombinedOutput()
	if err != nil {
		t.Fatalf("probe failed: %v %s", err, out)
	}
	var metric struct {
		CPU              float64 `json:"cpu"`
		Memory           float64 `json:"memory"`
		Disk             float64 `json:"disk"`
		Uptime           float64 `json:"uptime"`
		Service          string  `json:"service"`
		NetworkInterface string  `json:"network_interface"`
		DownloadMbps     float64 `json:"download_mbps"`
		UploadMbps       float64 `json:"upload_mbps"`
		DownloadBytes    int64   `json:"download_bytes"`
		UploadBytes      int64   `json:"upload_bytes"`
	}
	if err := json.Unmarshal(out, &metric); err != nil {
		t.Fatalf("probe invalid JSON %s: %v", out, err)
	}
	if metric.CPU < 0 || metric.CPU > 100 || metric.Memory < 0 || metric.Memory > 100 || metric.Disk < 0 || metric.Disk > 100 || metric.Uptime < 0 || metric.DownloadMbps < 0 || metric.UploadMbps < 0 || metric.DownloadBytes < 0 || metric.UploadBytes < 0 || metric.NetworkInterface == "" {
		t.Fatalf("invalid CPU/memory/disk/network metrics %+v", metric)
	}
}

func TestMonitorRefreshReturnsNetworkUsage(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("LINODE_TOKEN", "mock")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v4/linode/instances/5" {
			t.Errorf("unexpected Linode path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":5,"label":"monitor-test","status":"running","ipv4":["8.8.8.8"]}`))
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	s := testServer(upstream.Client())
	s.sshRun = func(_ context.Context, ip, script string) (string, error) {
		if ip != "8.8.8.8" || !strings.Contains(script, "download_mbps") {
			t.Errorf("unexpected SSH probe target or script")
		}
		return `{"cpu":10,"memory":20,"disk":30,"uptime":100,"service":"active","network_interface":"eth0","download_mbps":4.25,"upload_mbps":1.5,"download_bytes":2000,"upload_bytes":1000}`, nil
	}
	w := apiRequest(newHandler(s), "GET", "/api/monitor/refresh?account_id=legacy&instance_id=5", "")
	if w.Code != 200 {
		t.Fatalf("refresh failed: %d %s", w.Code, w.Body.String())
	}
	var snapshot Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.ID != 5 || snapshot.DownloadMbps != 4.25 || snapshot.UploadMbps != 1.5 || snapshot.DownloadBytes != 2000 || snapshot.UploadBytes != 1000 || snapshot.State != "online" || snapshot.NetworkInterface != "eth0" {
		t.Fatalf("unexpected refreshed metrics: %+v", snapshot)
	}
}

func TestMockMonitorAlertsAndTelegram(t *testing.T) {
	t.Setenv("LINODE_TOKEN", "mock")
	t.Setenv("TG_BOT_TOKEN", "mock-tg-token")
	t.Setenv("TG_CHAT_ID", "999")
	t.Setenv("ALERT_FAILURE_COUNT", "2")
	t.Setenv("ALERT_CPU_PERCENT", "90")
	t.Setenv("ALERT_MEMORY_PERCENT", "90")
	t.Setenv("ALERT_DISK_PERCENT", "90")
	messages := make(chan string, 8)
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4/linode/instances":
			_, _ = w.Write([]byte(`{"pages":1,"data":[{"id":45,"label":"mock-node","status":"running","ipv4":["8.8.8.8"]}]}`))
		case "/botmock-tg-token/sendMessage":
			if r.Method != "POST" {
				t.Errorf("Telegram method %s", r.Method)
			}
			_ = r.ParseForm()
			if r.Form.Get("chat_id") != "999" {
				t.Errorf("Telegram wrong chat id")
			}
			messages <- r.Form.Get("text")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Errorf("unexpected upstream path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	t.Setenv("LINODE_API_BASE_URL", upstream.URL+"/v4")
	t.Setenv("TG_API_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	var mode atomic.Int32
	s.sshRun = func(_ context.Context, _ string, _ string) (string, error) {
		switch mode.Load() {
		case 0:
			return `{"cpu":95,"memory":94,"disk":93,"uptime":100,"service":"active"}`, nil
		case 1:
			return `{"cpu":10,"memory":20,"disk":30,"uptime":200,"service":"active"}`, nil
		default:
			return "", errors.New("simulated SSH down")
		}
	}
	take := func(expected string) {
		t.Helper()
		select {
		case msg := <-messages:
			if !strings.Contains(msg, expected) {
				t.Fatalf("expected alert %q got %q", expected, msg)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no Telegram message for %q", expected)
		}
	}
	s.poll(context.Background())
	if got := s.status[45]; got.Alert != "cpu,memory,disk" || got.State != "online" {
		t.Fatalf("resource alerts incorrect: %+v", got)
	}
	take("cpu,memory,disk")
	s.poll(context.Background())
	select {
	case msg := <-messages:
		t.Fatalf("repeated alert: %s", msg)
	case <-time.After(100 * time.Millisecond):
	}
	mode.Store(1)
	s.poll(context.Background())
	if got := s.status[45]; got.Alert != "" || got.State != "online" {
		t.Fatalf("recovery wrong: %+v", got)
	}
	take("recovered")
	mode.Store(2)
	s.poll(context.Background())
	if got := s.status[45]; got.Alert != "" || got.Failures != 1 {
		t.Fatalf("first SSH failure should not alert: %+v", got)
	}
	s.poll(context.Background())
	if got := s.status[45]; got.Alert != "offline" || got.Failures != 2 {
		t.Fatalf("offline threshold incorrect: %+v", got)
	}
	take("offline")
}

func TestAlertsForThresholdAndService(t *testing.T) {
	t.Setenv("ALERT_CPU_PERCENT", "90")
	t.Setenv("ALERT_MEMORY_PERCENT", "80")
	t.Setenv("ALERT_DISK_PERCENT", "70")
	cases := []struct {
		v    Snapshot
		want string
	}{
		{Snapshot{CPU: 89, Memory: 79, Disk: 69, Service: "active"}, ""},
		{Snapshot{CPU: 90, Memory: 80, Disk: 70, Service: "active"}, "cpu,memory,disk"},
		{Snapshot{CPU: 1, Memory: 1, Disk: 1, Service: "inactive"}, "service"},
	}
	for _, tt := range cases {
		if got := alertsFor(tt.v); got != tt.want {
			t.Errorf("got alert %q want %q", got, tt.want)
		}
	}
}

func Example() {
	fmt.Println(shellQuote("some' text"))
	// Output: 'some'"'"' text'
}
