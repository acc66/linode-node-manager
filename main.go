package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	refillTasksMu      sync.Mutex
	refillTasks        map[string]*refillTaskRuntime
	refillMonitorSlots chan struct{}
	refillWait         func(context.Context, time.Duration) error
	refillReplaceIP    func(context.Context, string, Instance, int, string, bool) (Instance, *IPChange, error)
	linodeHook         func(context.Context, string, string, string, io.Reader) ([]byte, int, error)
	refillWaitPort     func(context.Context, string, int, int) (Instance, error)
	refillMu           sync.RWMutex
	egressLookup       func(context.Context, string) (string, error)
	wp2Mu              sync.Mutex
	client             *http.Client
	mu                 sync.RWMutex
	status             map[int]Snapshot
	accountStatus      map[string]Snapshot
	credentials        *accountStore
	accounts           *accountStore
	jobs               map[string]Job
	skipBootTuning     bool
	sshRun             func(context.Context, string, string) (string, error)
}
type Snapshot struct {
	AccountID        string  `json:"account_id,omitempty"`
	ID               int     `json:"id"`
	Label            string  `json:"label"`
	State            string  `json:"status"`
	CPU              float64 `json:"cpu"`
	Memory           float64 `json:"memory"`
	Disk             float64 `json:"disk"`
	Uptime           float64 `json:"uptime"`
	Service          string  `json:"service"`
	MonitorError     string  `json:"monitor_error,omitempty"`
	NetworkInterface string  `json:"network_interface,omitempty"`
	DownloadMbps     float64 `json:"download_mbps"`
	UploadMbps       float64 `json:"upload_mbps"`
	DownloadBytes    int64   `json:"download_bytes"`
	UploadBytes      int64   `json:"upload_bytes"`
	Failures         int     `json:"failures"`
	Alert            string  `json:"alert_state"`
	Updated          string  `json:"updated_at"`
}
type Job struct {
	Kind          string `json:"kind,omitempty"`
	HelperID      int    `json:"helper_id,omitempty"`
	HelperCleaned bool   `json:"helper_cleaned,omitempty"`
	IPChanged     bool   `json:"ip_changed,omitempty"`
	OldIP         string `json:"old_ip,omitempty"`
	NewIP         string `json:"new_ip,omitempty"`
	DNSStatus     string `json:"dns_status,omitempty"`
	InstanceID    int    `json:"instance_id,omitempty"`
	TargetID      int    `json:"target_id,omitempty"`
	TargetIDs     []int  `json:"target_ids,omitempty"`
	AccountID     string `json:"account_id,omitempty"`
	ID            string `json:"job_id"`
	Status        string `json:"status"`
	Log           string `json:"log"`
}
type Instance struct {
	InterfaceGeneration string   `json:"interface_generation,omitempty"`
	Image               string   `json:"image,omitempty"`
	DNSDomain           string   `json:"-"`
	AccountID           string   `json:"account_id,omitempty"`
	ID                  int      `json:"id"`
	Label               string   `json:"label"`
	Status              string   `json:"status"`
	IPv4                []string `json:"ipv4"`
	IPv6                string   `json:"ipv6"`
	Region              string   `json:"region"`
	Type                string   `json:"type"`
	PasswordSaved       bool     `json:"password_saved"`
	OpenAllPorts        bool     `json:"open_all_ports"`
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func number(k string, d int) int {
	v, e := strconv.Atoi(os.Getenv(k))
	if e != nil {
		return d
	}
	return v
}
func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, e string) {
	send(w, status, map[string]string{"error": e})
}
func safeEqual(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		browserSecurityHeaders(w)
		bearer := os.Getenv("ADMIN_TOKEN")
		user := os.Getenv("ADMIN_USERNAME")
		pass := os.Getenv("ADMIN_PASSWORD")
		authorized := false
		isBearer := false
		if v := r.Header.Get("Authorization"); bearer != "" && strings.HasPrefix(v, "Bearer ") {
			authorized = safeEqual(v, "Bearer "+bearer)
			isBearer = authorized
		} else if u, p, ok := r.BasicAuth(); ok && user != "" && len(pass) >= 12 {
			authorized = safeEqual(u, user) && safeEqual(p, pass)
		} else if r.Header.Get("Authorization") == "" {
			authorized = validBrowserSession(r)
		}
		if !authorized {
			if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			w.Header().Set("X-LNM-Auth-Required", "true")
			fail(w, 401, "Unauthorized")
			return
		}
		if (r.Method == "POST" || r.Method == "DELETE" || r.Method == "PUT" || r.Method == "PATCH") && !isBearer {
			if !sameBrowserOrigin(r) {
				fail(w, 403, "Cross-origin request rejected")
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				fail(w, 415, "JSON content type required")
				return
			}
		}
		next(w, r.WithContext(useProxyContext(r.Context(), r.URL.Query().Get("use_proxy") == "true")))
	}
}
func (s *Server) request(ctx context.Context, method, endpoint, token string, payload io.Reader) ([]byte, int, error) {
	req, e := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if e != nil {
		return nil, 0, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := s.client.Do(req)
	if e != nil {
		return nil, 0, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, e
}
func (s *Server) linode(ctx context.Context, method, path string, payload io.Reader) ([]byte, int, error) {
	return s.linodeFor(ctx, "", method, path, payload)
}
func (s *Server) instances(ctx context.Context) ([]Instance, error) { return s.instancesFor(ctx, "") }
func (s *Server) instancesFor(ctx context.Context, accountID string) ([]Instance, error) {
	out := []Instance{}
	for page := 1; page <= 100; page++ {
		b, status, e := s.linodeFor(ctx, accountID, "GET", fmt.Sprintf("/linode/instances?page=%d&page_size=100", page), nil)
		if e != nil {
			return nil, e
		}
		if status != 200 {
			return nil, fmt.Errorf("Linode HTTP %d", status)
		}
		var data struct {
			Data  []Instance `json:"data"`
			Pages int        `json:"pages"`
		}
		if e = json.Unmarshal(b, &data); e != nil {
			return nil, e
		}
		for _, inst := range data.Data {
			inst.AccountID = accountID
			if inst.AccountID == "" {
				inst.AccountID = "legacy"
			}
			inst.PasswordSaved = s.passwordSaved(inst.AccountID, inst.ID)
			inst.OpenAllPorts = s.openPortsSaved(inst.AccountID, inst.ID)
			out = append(out, inst)
		}
		if page >= data.Pages {
			break
		}
	}
	return out, nil
}
func (s *Server) wpNodes(w http.ResponseWriter, r *http.Request) {
	s.wp2Mu.Lock()
	defer s.wp2Mu.Unlock()
	session, err := s.loadWP2Session()
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	if session != nil {
		nodes, err := s.adminWP2Nodes(r.Context(), session)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, map[string]any{"nodes": nodes, "source": "wp2-admin"})
		return
	}

	base := env("WP2_BASE_URL", "")
	token := os.Getenv("WP2_API_TOKEN")
	path := env("WP2_NODES_PATH", "/mod_mu/nodes")
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		fail(w, 503, "Configure HTTPS WP2_BASE_URL")
		return
	}
	if token == "" {
		fail(w, 503, "Configure WP2_API_TOKEN")
		return
	}
	if path != "/mod_mu/nodes" {
		fail(w, 400, "Unsupported node-list path")
		return
	}
	target := strings.TrimRight(base, "/") + path + "?key=" + url.QueryEscape(token) + "&view=manager"
	req, e := http.NewRequestWithContext(r.Context(), "GET", target, nil)
	if e != nil {
		fail(w, 500, "Invalid request")
		return
	}
	resp, e := s.client.Do(req)
	if e != nil {
		fail(w, 502, "wp2 unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(w, 502, fmt.Sprintf("wp2 HTTP %d", resp.StatusCode))
		return
	}
	var data struct {
		Ret         int             `json:"ret"`
		Data        json.RawMessage `json:"data"`
		ManagerView bool            `json:"manager_view"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&data); e != nil || data.Ret != 1 {
		fail(w, 502, "wp2 returned invalid or rejected response")
		return
	}
	var nodes []map[string]any
	if len(data.Data) == 0 || strings.TrimSpace(string(data.Data)) == "null" {
		fail(w, 502, "wp2 returned null node data, not a node list; check WebAPI and source IP permissions")
		return
	}
	if e = json.Unmarshal(data.Data, &nodes); e != nil {
		fail(w, 502, "wp2 nodes response malformed")
		return
	}
	// Never forward credentials or full node configuration to the browser.
	safe := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		// wp2 /mod_mu/nodes is a node configuration listing, not a live heartbeat feed.
		safe = append(safe, map[string]any{"id": n["id"], "name": n["name"], "sort": n["sort"], "node_status": "unknown", "status_source": "wp2 node listing; no heartbeat"})
	}
	warning := ""
	if len(safe) == 0 {
		warning = "wp2 返回空节点列表。旧接口仅支持 sort=0/10/12/13 且要求有 node_ip；请部署 wp2 管理视图补丁。"
	}
	if len(safe) == 0 && data.ManagerView {
		warning = "wp2 管理视图返回空列表，请检查当前 wp2 连接的数据库是否有节点记录。"
	}
	send(w, 200, map[string]any{"nodes": safe, "warning": warning, "manager_view": data.ManagerView})
}
func ssh(ctx context.Context, ip, script string) (string, error) {
	key := env("SSH_PRIVATE_KEY_PATH", "/run/secrets/linode_ssh_key")
	known := env("SSH_KNOWN_HOSTS_PATH", "/run/secrets/known_hosts")
	if _, e := os.Stat(key); e != nil {
		return "", errors.New("SSH private key not configured")
	}
	if _, e := os.Stat(known); e != nil {
		return "", errors.New("SSH known_hosts not configured")
	}
	user := env("MONITOR_SSH_USER", "root")
	cmd := exec.CommandContext(ctx, "ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+known, "-o", "ConnectTimeout=8", user+"@"+ip, "bash -s")
	cmd.Stdin = strings.NewReader(script)
	b, e := cmd.CombinedOutput()
	return string(b), e
}
func (s *Server) runSSH(ctx context.Context, ip, script string) (string, error) {
	if s.sshRun != nil {
		return s.sshRun(ctx, ip, script)
	}
	return ssh(ctx, ip, script)
}
func publicIP(i Instance) string {
	for _, v := range i.IPv4 {
		ip := net.ParseIP(v)
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return v
		}
	}
	return ""
}

const probeScript = `python3 - <<'PY'
import json,os,time,subprocess
def cpu():
 a=list(map(int,open('/proc/stat').readline().split()[1:]));return sum(a),a[3]+a[4]
def network():
 rows={}
 for line in open('/proc/net/dev').read().splitlines()[2:]:
  name,values=line.split(':',1);name=name.strip();fields=list(map(int,values.split()));rows[name]=(fields[0],fields[8])
 try:
  for line in open('/proc/net/route').read().splitlines()[1:]:
   fields=line.split()
   if fields[1]=='00000000' and int(fields[3],16)&1 and fields[0] in rows:return fields[0],*rows[fields[0]]
 except (OSError,ValueError,IndexError):pass
 usable={name:counts for name,counts in rows.items() if name!='lo' and not name.startswith(('docker','br-','veth','virbr','tun','wg'))}
 return 'all interfaces',sum(v[0] for v in usable.values()),sum(v[1] for v in usable.values())
a,b=cpu();time.sleep(.25);c,d=cpu()
interface,rx1,tx1=network();time.sleep(.25);_,rx2,tx2=network()
m={}
for line in open('/proc/meminfo'):
 k,v=line.split(':',1);m[k]=int(v.split()[0])
st=os.statvfs('/');total=st.f_blocks*st.f_frsize;free=st.f_bavail*st.f_frsize
svc=subprocess.run(['systemctl','is-active','xboard-node.service'],capture_output=True,text=True,timeout=5).stdout.strip()
seconds=.25
print(json.dumps({'cpu':round(100*(1-(d-b)/max(1,c-a)),1),'memory':round(100*(1-m.get('MemAvailable',0)/max(1,m.get('MemTotal',1))),1),'disk':round(100*(1-free/max(1,total)),1),'uptime':int(float(open('/proc/uptime').read().split()[0])),'service':svc,'network_interface':interface,'download_mbps':round(max(0,rx2-rx1)*8/seconds/1000000,3),'upload_mbps':round(max(0,tx2-tx1)*8/seconds/1000000,3),'download_bytes':rx2,'upload_bytes':tx2}))
PY
`

func (s *Server) telegram(msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.sendTelegram(ctx, msg)
}
func alertsFor(next Snapshot) string {
	alarms := []string{}
	for _, v := range []struct {
		Name  string
		Value float64
		Limit int
	}{{"cpu", next.CPU, number("ALERT_CPU_PERCENT", 90)}, {"memory", next.Memory, number("ALERT_MEMORY_PERCENT", 90)}, {"disk", next.Disk, number("ALERT_DISK_PERCENT", 90)}} {
		if v.Value >= float64(v.Limit) {
			alarms = append(alarms, v.Name)
		}
	}
	if next.Service != "active" {
		alarms = append(alarms, "service")
	}
	return strings.Join(alarms, ",")
}
func (s *Server) poll(ctx context.Context) {
	items, e := s.instances(ctx)
	if e != nil {
		log.Printf("monitor: Linode list unavailable: %v", e)
		return
	}
	for _, inst := range items {
		old := Snapshot{}
		s.mu.RLock()
		old = s.status[inst.ID]
		s.mu.RUnlock()
		next := Snapshot{AccountID: "legacy", ID: inst.ID, Label: inst.Label, State: "offline", Updated: time.Now().UTC().Format(time.RFC3339)}
		if inst.Status == "running" && publicIP(inst) != "" {
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			output, err := s.deploySSH(c, "legacy", inst, probeScript)
			cancel()
			if err == nil {
				var v struct {
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
				if json.Unmarshal([]byte(output), &v) == nil && v.CPU >= 0 && v.CPU <= 100 && v.Memory >= 0 && v.Memory <= 100 && v.Disk >= 0 && v.Disk <= 100 && v.Uptime >= 0 {
					next.State = "online"
					next.CPU = v.CPU
					next.Memory = v.Memory
					next.Disk = v.Disk
					next.Uptime = v.Uptime
					next.Service = v.Service
					next.NetworkInterface = v.NetworkInterface
					next.DownloadMbps = v.DownloadMbps
					next.UploadMbps = v.UploadMbps
					next.DownloadBytes = v.DownloadBytes
					next.UploadBytes = v.UploadBytes
				} else {
					next.MonitorError = "SSH 探针返回无效监控数据"
				}
			} else {
				next.MonitorError = err.Error()
			}
		} else if inst.Status == "running" {
			next.MonitorError = "Linode 实例没有公网 IPv4 地址"
		} else {
			next.MonitorError = "Linode 实例状态：" + inst.Status
		}
		if next.State == "offline" {
			next.Failures = old.Failures + 1
			if next.Failures >= number("ALERT_FAILURE_COUNT", 3) {
				next.Alert = "offline"
			}
		} else {
			next.Alert = alertsFor(next)
		}
		s.mu.Lock()
		s.status[inst.ID] = next
		s.mu.Unlock()
		if next.Alert != old.Alert {
			if next.Alert != "" {
				go s.telegram(fmt.Sprintf("🚨 Linode %s (#%d): %s", inst.Label, inst.ID, next.Alert))
			}
			if next.Alert == "" && old.Alert != "" {
				go s.telegram(fmt.Sprintf("✅ Linode %s (#%d) recovered", inst.Label, inst.ID))
			}
		}
	}
}
func (s *Server) monitoring(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(max(30, number("MONITOR_INTERVAL", 60))) * time.Second)
	defer ticker.Stop()
	s.poll(ctx)
	s.pollAccounts(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll(ctx)
			s.pollAccounts(ctx)
		}
	}
}
func jobsShareTargets(job Job, targets []int) bool {
	jobTargets := job.TargetIDs
	if len(jobTargets) == 0 && job.TargetID > 0 {
		jobTargets = []int{job.TargetID}
	}
	for _, old := range jobTargets {
		for _, target := range targets {
			if old == target {
				return true
			}
		}
	}
	return false
}
func (s *Server) monitorRefreshAPI(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account_id")
	if account == "" {
		fail(w, 400, "请先选择一个 Linode 账号")
		return
	}
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "Linode 账号未配置或已移除")
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("instance_id"))
	if err != nil || id <= 0 {
		fail(w, 400, "请选择要实时采样的 Linode 实例")
		return
	}
	body, status, err := s.linodeFor(r.Context(), account, http.MethodGet, fmt.Sprintf("/linode/instances/%d", id), nil)
	if err != nil || status != http.StatusOK {
		fail(w, 502, "读取 Linode 实例失败，请检查账号 Token 与代理")
		return
	}
	var instance Instance
	if json.Unmarshal(body, &instance) != nil {
		fail(w, 502, "Linode 实例数据格式无效")
		return
	}
	next := Snapshot{AccountID: account, ID: id, Label: instance.Label, State: "offline", Updated: time.Now().UTC().Format(time.RFC3339)}
	old := Snapshot{}
	key := account + "/" + strconv.Itoa(id)
	s.mu.RLock()
	if account == "legacy" {
		old = s.status[id]
	} else {
		old = s.accountStatus[key]
	}
	s.mu.RUnlock()
	if instance.Status != "running" {
		next.MonitorError = "Linode 实例状态：" + instance.Status
	} else if publicIP(instance) == "" {
		next.MonitorError = "Linode 实例没有公网 IPv4 地址"
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		output, probeErr := s.deploySSH(ctx, account, instance, probeScript)
		cancel()
		if probeErr != nil {
			next.MonitorError = probeErr.Error()
		} else {
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
			if json.Unmarshal([]byte(output), &metric) != nil || metric.CPU < 0 || metric.CPU > 100 || metric.Memory < 0 || metric.Memory > 100 || metric.Disk < 0 || metric.Disk > 100 || metric.DownloadMbps < 0 || metric.UploadMbps < 0 || metric.DownloadBytes < 0 || metric.UploadBytes < 0 {
				next.MonitorError = "SSH 探针返回无效监控数据"
			} else {
				next.State = "online"
				next.CPU = metric.CPU
				next.Memory = metric.Memory
				next.Disk = metric.Disk
				next.Uptime = metric.Uptime
				next.Service = metric.Service
				next.NetworkInterface = metric.NetworkInterface
				next.DownloadMbps = metric.DownloadMbps
				next.UploadMbps = metric.UploadMbps
				next.DownloadBytes = metric.DownloadBytes
				next.UploadBytes = metric.UploadBytes
				next.Alert = alertsFor(next)
			}
		}
	}
	if next.State != "online" {
		next.Failures = old.Failures + 1
		if next.Failures >= number("ALERT_FAILURE_COUNT", 3) {
			next.Alert = "offline"
		}
	}
	s.mu.Lock()
	if account == "legacy" {
		if s.status == nil {
			s.status = map[int]Snapshot{}
		}
		s.status[id] = next
	} else {
		if s.accountStatus == nil {
			s.accountStatus = map[string]Snapshot{}
		}
		s.accountStatus[key] = next
	}
	s.mu.Unlock()
	send(w, 200, next)
}
func (s *Server) install(w http.ResponseWriter, r *http.Request) {
	if !s.refillMu.TryRLock() {
		fail(w, 409, "补号或账户运维正在运行，请等待")
		return
	}
	defer s.refillMu.RUnlock()
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		accountID = "legacy"
	}
	if _, err := s.accountToken(accountID); err != nil {
		fail(w, 400, "Unknown or unconfigured Linode account")
		return
	}
	var in struct {
		InstanceID int    `json:"instance_id"`
		Mode       string `json:"mode"`
		Operation  string `json:"operation"`
		TargetID   int    `json:"target_id"`
		TargetIDs  []int  `json:"target_ids"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil || in.InstanceID <= 0 || in.Mode != "node" {
		fail(w, 400, "Valid instance_id and node mode required")
		return
	}
	if in.Operation == "" {
		in.Operation = "add"
	}
	if in.Operation != "add" && in.Operation != "replace" {
		fail(w, 400, "operation must be add or replace")
		return
	}
	if len(in.TargetIDs) == 0 && in.TargetID > 0 {
		in.TargetIDs = []int{in.TargetID}
	}
	if len(in.TargetIDs) == 0 || len(in.TargetIDs) > 20 {
		fail(w, 400, "请至少选择一个节点，最多可一次安装 20 个")
		return
	}
	seenTargets := map[int]bool{}
	for _, target := range in.TargetIDs {
		if target <= 0 || seenTargets[target] {
			fail(w, 400, "节点 ID 无效或重复")
			return
		}
		seenTargets[target] = true
	}
	in.TargetID = in.TargetIDs[0]
	token := os.Getenv("WP2_API_TOKEN")
	base := env("WP2_BASE_URL", "")
	u, e := url.Parse(base)
	if token == "" || e != nil || u.Scheme != "https" || u.Host == "" {
		fail(w, 503, "wp2 not configured")
		return
	}
	b, st, e := s.linodeFor(r.Context(), accountID, "GET", fmt.Sprintf("/linode/instances/%d", in.InstanceID), nil)
	if e != nil || st != 200 {
		fail(w, 502, "Linode instance lookup failed")
		return
	}
	var inst Instance
	if json.Unmarshal(b, &inst) != nil || inst.Status != "running" || publicIP(inst) == "" {
		fail(w, 409, "Running public IPv4 instance required")
		return
	}
	inst.OpenAllPorts = s.openPortsSaved(accountID, inst.ID)
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	s.mu.Lock()
	for _, job := range s.jobs {
		if (job.Status == "queued" || job.Status == "running") && ((job.AccountID == accountID && job.InstanceID == in.InstanceID) || jobsShareTargets(job, in.TargetIDs)) {
			s.mu.Unlock()
			fail(w, 409, "该服务器或 wp2 节点正在安装，请等待当前任务完成")
			return
		}
	}
	s.jobs[id] = Job{ID: id, AccountID: accountID, InstanceID: in.InstanceID, TargetID: in.TargetID, TargetIDs: append([]int(nil), in.TargetIDs...), Status: "queued"}
	s.mu.Unlock()
	go func() {
		s.mu.Lock()
		s.jobs[id] = Job{ID: id, AccountID: accountID, InstanceID: in.InstanceID, TargetID: in.TargetID, TargetIDs: append([]int(nil), in.TargetIDs...), Status: "running"}
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		dnsReady := false
		dnsDomainMap := map[int]string{}
		dnsStatus := "skipped"
		prefix := ""
		var err error
		for _, target := range in.TargetIDs {
			inst.DNSDomain = ""
			ready, nodeLog, dnsErr := s.prepareDeploymentDNS(ctx, base, token, target, &inst)
			prefix += fmt.Sprintf("── wp2 节点 #%d ──\n", target) + nodeLog
			if inst.DNSDomain != "" {
				dnsDomainMap[target] = inst.DNSDomain
			}
			if ready {
				dnsReady = true
				dnsStatus = "updated"
			}
			if dnsErr != nil {
				err = dnsErr
				dnsStatus = "failed"
				break
			}
		}
		output := prefix
		if err == nil {
			s.mu.Lock()
			current := s.jobs[id]
			current.Log = prefix
			current.DNSStatus = dnsStatus
			s.jobs[id] = current
			s.mu.Unlock()
			script := deploymentScript(base, token, in.TargetIDs, inst, dnsReady, dnsDomainMap, in.Operation)
			var remote string
			remote, err = s.deploySSH(ctx, accountID, inst, script, func(progress string) {
				text := prefix + progress
				if len(text) > 16000 {
					text = text[len(text)-16000:]
				}
				s.mu.Lock()
				current := s.jobs[id]
				current.Log = text
				current.DNSStatus = dnsStatus
				s.jobs[id] = current
				s.mu.Unlock()
			})
			output += remote
		}
		output = strings.ReplaceAll(output, token, "[REDACTED]")
		if len(output) > 16000 {
			output = output[len(output)-16000:]
		}
		state := "success"
		if err != nil {
			state = "failed"
			output += "\nInstallation failed: " + err.Error()
			if dnsReady {
				output += "\nDNS 记录已更新并保留，可修复问题后重新安装。"
			}
		}
		if state == "success" {
			bindings, _ := json.Marshal(in.TargetIDs)
			if bindErr := s.saveRootPassword("ddns-bindings-"+accountID, inst.ID, inst.Label, string(bindings)); bindErr != nil {
				state = "partial"
				output += "\n后端已安装，但 DDNS 绑定保存失败：" + bindErr.Error()
			} else {
				output += fmt.Sprintf("\nDDNS 绑定已保存：服务器 #%d → wp2 节点 %v；换 IP 后自动更新绑定域名。\n", inst.ID, in.TargetIDs)
			}
			if bindErr := s.saveRootPassword("node-binding-"+accountID, inst.ID, inst.Label, strconv.Itoa(in.TargetIDs[0])); bindErr != nil {
				state = "partial"
				output += "\n默认节点绑定保存失败：" + bindErr.Error()
			}
		}
		s.mu.Lock()
		s.jobs[id] = Job{ID: id, AccountID: accountID, InstanceID: in.InstanceID, TargetID: in.TargetID, TargetIDs: append([]int(nil), in.TargetIDs...), Status: state, Log: output, DNSStatus: dnsStatus}
		s.mu.Unlock()
	}()
	send(w, 202, map[string]string{"job_id": id, "status": "queued"})
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func newHandler(s *Server) http.Handler {
	mux := http.NewServeMux()
	s.registerRefill(mux)
	mux.HandleFunc("GET /api/account-pool", s.auth(s.accountPoolAPI))
	mux.HandleFunc("PUT /api/account-pool", s.auth(s.accountPoolAPI))
	mux.HandleFunc("POST /api/accounts/{id}/egress", s.auth(s.accountEgressAPI))
	mux.HandleFunc("POST /api/accounts/bulk", s.auth(s.accountBulkAPI))
	mux.HandleFunc("DELETE /api/accounts/bulk", s.auth(s.accountBulkAPI))
	mux.HandleFunc("PUT /api/account-pool/bindings", s.auth(s.accountBulkBindingsAPI))
	mux.HandleFunc("GET /login", s.browserLogin)
	mux.HandleFunc("POST /login", s.browserLogin)
	mux.HandleFunc("POST /api/logout", s.auth(s.browserLogout))
	mux.HandleFunc("PATCH /api/proxy-pool/{id}", s.auth(s.proxyPoolEntryAPI))
	mux.HandleFunc("GET /api/ip-changes", s.auth(s.ipChangeListAPI))
	mux.HandleFunc("GET /api/instances/{id}/ip-change-plan", s.auth(s.ipChangePlanAPI))
	mux.HandleFunc("POST /api/instances/{id}/change-ip", s.auth(s.ipChangeAPI))
	mux.HandleFunc("POST /api/ip-changes/{job}/cleanup", s.auth(s.ipChangeCleanupAPI))
	mux.HandleFunc("GET /api/instances/{id}/backend/logs", s.auth(s.backendLogsAPI))
	mux.HandleFunc("POST /api/dns/discover", s.auth(s.dnsDiscoverAPI))
	mux.HandleFunc("GET /api/telegram/settings", s.auth(s.telegramSettingsAPI))
	mux.HandleFunc("POST /api/telegram/settings", s.auth(s.telegramSettingsAPI))
	mux.HandleFunc("DELETE /api/telegram/settings", s.auth(s.telegramSettingsAPI))
	mux.HandleFunc("POST /api/telegram/test", s.auth(s.telegramTestAPI))
	mux.HandleFunc("GET /api/dns/providers", s.auth(s.dnsProvidersAPI))
	mux.HandleFunc("POST /api/dns/providers", s.auth(s.dnsProvidersAPI))
	mux.HandleFunc("PATCH /api/dns/providers", s.auth(s.dnsProvidersAPI))
	mux.HandleFunc("DELETE /api/dns/providers", s.auth(s.dnsProvidersAPI))
	mux.HandleFunc("GET /api/domestic-probe/settings", s.auth(s.domesticProbeSettingsAPI))
	mux.HandleFunc("POST /api/domestic-probe/settings", s.auth(s.domesticProbeSettingsAPI))
	mux.HandleFunc("DELETE /api/domestic-probe/settings", s.auth(s.domesticProbeSettingsAPI))
	mux.HandleFunc("GET /api/iptrace-probe/settings", s.auth(s.ipTraceProbeSettingsAPI))
	mux.HandleFunc("POST /api/iptrace-probe/settings", s.auth(s.ipTraceProbeSettingsAPI))
	mux.HandleFunc("DELETE /api/iptrace-probe/settings", s.auth(s.ipTraceProbeSettingsAPI))
	mux.HandleFunc("PUT /api/china-probe/provider", s.auth(s.chinaProbeProviderAPI))
	mux.HandleFunc("GET /api/china-probe/boot-settings", s.auth(s.chinaBootSettingsAPI))
	mux.HandleFunc("POST /api/china-probe/boot-settings", s.auth(s.chinaBootSettingsAPI))
	mux.HandleFunc("GET /api/dns/check", s.auth(s.dnsCheckAPI))
	mux.HandleFunc("GET /api/proxy-pool", s.auth(s.proxyPoolAPI))
	mux.HandleFunc("POST /api/proxy-pool", s.auth(s.proxyPoolAPI))
	mux.HandleFunc("PUT /api/proxy-pool", s.auth(s.proxyPoolAPI))
	mux.HandleFunc("GET /api/linode/proxy", s.auth(s.linodeProxyAPI))
	mux.HandleFunc("PUT /api/linode/proxy", s.auth(s.linodeProxyAPI))
	mux.HandleFunc("DELETE /api/linode/proxy", s.auth(s.linodeProxyAPI))
	mux.HandleFunc("GET /api/wp2/session", s.auth(s.wp2SessionAPI))
	mux.HandleFunc("POST /api/wp2/session", s.auth(s.wp2SessionAPI))
	mux.HandleFunc("DELETE /api/wp2/session", s.auth(s.wp2SessionAPI))
	mux.HandleFunc("GET /api/instances/{id}/password", s.auth(s.instancePassword))
	mux.HandleFunc("PUT /api/instances/{id}/password", s.auth(s.saveInstancePassword))
	mux.HandleFunc("DELETE /api/instances/{id}", s.auth(s.deleteInstance))
	mux.HandleFunc("POST /api/instances", s.auth(s.createInstance))
	mux.HandleFunc("GET /api/catalog/{kind}", s.auth(s.catalog))
	mux.HandleFunc("GET /", s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, htmlPage)
	}))
	mux.HandleFunc("GET /api/health", s.auth(func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]string{"status": "ok", "language": "go"})
	}))
	mux.HandleFunc("GET /api/instances", s.auth(func(w http.ResponseWriter, r *http.Request) {
		accountID := r.URL.Query().Get("account_id")
		items := []Instance{}
		ids := []string{}
		if accountID != "" {
			if _, err := s.accountToken(accountID); err != nil {
				fail(w, 400, "Unknown account")
				return
			}
			ids = append(ids, accountID)
		} else {
			if s.legacyEnabled() {
				ids = append(ids, "legacy")
			}
			if s.accounts != nil {
				for _, a := range s.accounts.list() {
					ids = append(ids, a.ID)
				}
			}
		}
		for _, id := range ids {
			found, err := s.instancesFor(r.Context(), id)
			if err != nil {
				fail(w, 502, "Linode API unavailable for selected account")
				return
			}
			items = append(items, found...)
		}
		send(w, 200, map[string]any{"instances": items})
	}))
	mux.HandleFunc("GET /api/instances/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		id, e := strconv.Atoi(r.PathValue("id"))
		if e != nil || id <= 0 {
			fail(w, 400, "Invalid instance ID")
			return
		}
		b, st, e := s.linodeFor(r.Context(), r.URL.Query().Get("account_id"), "GET", fmt.Sprintf("/linode/instances/%d", id), nil)
		if e != nil {
			fail(w, 502, "Linode API unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		w.Write(b)
	}))
	mux.HandleFunc("GET /api/wp2/nodes", s.auth(s.wpNodes))
	mux.HandleFunc("GET /api/accounts", s.auth(s.accountsAPI))
	mux.HandleFunc("POST /api/accounts", s.auth(s.accountsAPI))
	mux.HandleFunc("DELETE /api/accounts/{id}", s.auth(s.deleteAccount))
	mux.HandleFunc("GET /api/accounts/{id}/billing", s.auth(s.accountBilling))
	mux.HandleFunc("GET /api/monitor", s.auth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		items := []Snapshot{}
		for _, v := range s.status {
			items = append(items, v)
		}
		for _, v := range s.accountStatus {
			items = append(items, v)
		}
		send(w, 200, map[string]any{"instances": items})
	}))
	mux.HandleFunc("GET /api/monitor/refresh", s.auth(s.monitorRefreshAPI))
	mux.HandleFunc("POST /api/deployments/install", s.auth(s.install))
	mux.HandleFunc("GET /api/deployments/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		v, ok := s.jobs[r.PathValue("id")]
		s.mu.RUnlock()
		if !ok {
			if op, err := s.loadIPChange(r.PathValue("id")); err == nil {
				v = op.Job
				ok = true
				if v.Status == "queued" || v.Status == "running" {
					v.Status = "interrupted"
					v.Log += "\n管理程序重启，换 IP 未自动继续。请核对原机/临时实例及计费状态，必要时清理临时实例。"
				}
			}
		}
		if !ok {
			fail(w, 404, "Unknown job")
			return
		}
		send(w, 200, v)
	}))
	mux.HandleFunc("POST /api/instances/{id}/{action}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !s.refillMu.TryRLock() {
			fail(w, 409, "补号任务正在运行")
			return
		}
		defer s.refillMu.RUnlock()
		id, e := strconv.Atoi(r.PathValue("id"))
		action := r.PathValue("action")
		if e != nil || id <= 0 || (action != "boot" && action != "shutdown" && action != "reboot") {
			fail(w, 400, "Invalid action")
			return
		}
		if s.instanceChangingIP(r.URL.Query().Get("account_id"), id) {
			fail(w, 409, "该实例正在换 IP，请等待任务完成")
			return
		}
		b, st, e := s.linodeFor(r.Context(), r.URL.Query().Get("account_id"), "POST", fmt.Sprintf("/linode/instances/%d/%s", id, action), strings.NewReader("{}"))
		if e != nil {
			fail(w, 502, "Linode API unavailable")
			return
		}
		if st >= 200 && st < 300 && (action == "boot" || action == "reboot") {
			enabled, _ := r.Context().Value(proxyContextKey{}).(bool)
			if jobID := s.queueBootTuning(r.URL.Query().Get("account_id"), id, enabled); jobID != "" {
				send(w, st, map[string]string{"status": "boot_requested", "boot_job_id": jobID})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		w.Write(b)
	}))
	return mux
}
func main() {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if err := validateAdminConfig(); err != nil {
		log.Fatal("Invalid administrator configuration: ", err)
	}
	s := &Server{client: &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, status: map[int]Snapshot{}, accountStatus: map[string]Snapshot{}, jobs: map[string]Job{}}
	if key := os.Getenv("ACCOUNT_ENCRYPTION_KEY"); key != "" {
		store, err := initAccounts(env("ACCOUNTS_FILE", "/data/accounts.enc"), key)
		if err != nil {
			log.Fatal("Cannot load encrypted accounts: ", err)
		}
		s.accounts = store
		credentials, err := initAccounts(env("INSTANCE_CREDENTIALS_FILE", "/data/instance-credentials.enc"), key)
		if err != nil {
			log.Fatal("Cannot load encrypted instance credentials: ", err)
		}
		s.credentials = credentials
	}

	mux := newHandler(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.refillScheduler(ctx)
	// The dashboard's CPU/RAM/Disk cards depend on this poller. Start it by
	// default; deployments can still opt out explicitly for constrained hosts.
	if env("MONITOR_ENABLED", "true") != "false" {
		go s.monitoring(ctx)
	}
	addr := env("LISTEN_ADDR", "0.0.0.0:8000")
	log.Printf("Linode Node Manager Go listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
func validateAdminConfig() error {
	user, pass := os.Getenv("ADMIN_USERNAME"), os.Getenv("ADMIN_PASSWORD")
	if user != "" || pass != "" {
		if user == "" {
			return errors.New("ADMIN_USERNAME is required when ADMIN_PASSWORD is set")
		}
		if len(pass) < 12 {
			return errors.New("ADMIN_PASSWORD must be at least 12 characters; update .env and recreate the manager container")
		}
	} else if os.Getenv("ADMIN_TOKEN") == "" {
		return errors.New("configure ADMIN_USERNAME and ADMIN_PASSWORD, or ADMIN_TOKEN for API-only access")
	}
	return nil
}

const htmlPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta name="theme-color" content="#0b1120"><title>Linode 节点管理</title>
<style>
:root{color-scheme:dark;--bg:#0b1120;--surface:#111c30;--raised:#18263e;--line:#283953;--text:#e8eef9;--muted:#9aaec8;--blue:#5499ff;--green:#5ed5b0;--red:#ff939d;--radius:18px}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:radial-gradient(ellipse at 5% 0%,#152a49 0,transparent 45%),var(--bg);color:var(--text);font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer;min-height:42px;padding:9px 15px;border:1px solid var(--line);border-radius:11px;background:var(--raised);color:var(--text);font-weight:600;transition:background .15s,border-color .15s}button:hover:not(:disabled){background:#223753;border-color:#5e7fa9}button:disabled{opacity:.4;cursor:not-allowed}.primary{background:#397eea;border-color:#397eea;color:#fff}.primary:hover:not(:disabled){background:#4b90fc}.danger{color:var(--red)}a{color:inherit;text-decoration:none}button,input,select,a,summary{-webkit-tap-highlight-color:transparent}button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--blue);outline-offset:3px}input,select{min-width:0;width:100%;min-height:44px;background:#0d1728;border:1px solid #344763;border-radius:10px;padding:10px 12px;color:var(--text);font-size:16px}input::placeholder{color:#8194ad}input[type=checkbox]{width:19px;min-height:19px;height:19px;flex-shrink:0;accent-color:#548ff4;margin:0}label{display:flex;flex-direction:column;gap:7px;color:var(--muted);font-size:13px}.check{display:flex;flex-direction:row;align-items:center;gap:10px;min-height:44px;color:var(--text)}.topbar{position:sticky;top:0;z-index:20;background:#0b1120ed;border-bottom:1px solid #24354f;backdrop-filter:blur(16px)}.top-inner{max-width:1180px;margin:auto;padding:15px 24px;display:flex;justify-content:space-between;align-items:center;gap:16px}.brand{display:flex;align-items:center;gap:12px}.brand-mark{width:38px;height:38px;display:grid;place-items:center;background:#23457a;border:1px solid #3c6eb4;border-radius:12px;color:#a9ceff;font-weight:800;font-size:20px}.brand strong{font-size:16px;letter-spacing:.2px}.brand small{display:block;color:var(--muted);font-size:11px;line-height:1.3}.secure{font-size:12px;color:var(--green);border:1px solid #244d49;background:#12302d;padding:4px 10px;border-radius:30px}.shell{max-width:1180px;padding:28px 24px 48px;margin:auto}.hero{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:24px}.eyebrow{font-size:11px;color:var(--blue);letter-spacing:1.8px;font-weight:700;text-transform:uppercase}.hero h1{margin:4px 0 8px;font-size:28px;line-height:1.3;letter-spacing:-.8px}.hero p{color:var(--muted);margin:0;max-width:540px}.navigation{display:flex;gap:5px;background:#111c30;border:1px solid var(--line);border-radius:14px;padding:5px;margin:0 0 24px}.navigation a{padding:10px 16px;border-radius:9px;color:var(--muted);font-size:13px;font-weight:600}.navigation a:hover{background:#223753;color:var(--text)}section{border:1px solid var(--line);border-radius:var(--radius);background:linear-gradient(120deg,#152238bb,#111c30);padding:22px;margin:0 0 20px;scroll-margin-top:88px}.section-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:17px}.section-header h2{font-size:18px;margin:0;letter-spacing:-.3px}.section-header p{margin:4px 0 0;color:var(--muted);font-size:12px}.tag{padding:3px 9px;border:1px solid #34567b;color:#a5c9f5;border-radius:7px;font-size:11px;white-space:nowrap}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}.span-all{grid-column:1/-1}.toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:9px}.toolbar>*{flex:0 0 auto}.toolbar input{flex:1 1 180px}.action-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:18px;padding-top:17px;border-top:1px solid var(--line)}.hint{font-size:12px;color:var(--muted);margin:10px 0 0}.message{font-size:13px;color:#bed5fa;overflow-wrap:anywhere;margin:12px 0 0;white-space:pre-wrap}.message:empty{display:none}.subpanel{margin-top:18px;padding-top:15px;border-top:1px solid var(--line)}details>summary{cursor:pointer;min-height:42px;display:list-item;color:#a6c8f5;font-weight:600;font-size:13px;list-style-position:inside}details[open]>summary{margin-bottom:15px}.reveal{margin-top:17px;background:#0e182a;border:1px solid #273953;border-radius:12px;padding:12px 14px}.table-wrap{overflow-x:auto;width:100%;border:1px solid var(--line);border-radius:12px;background:#0d1728}table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}th{background:#1a2940;color:#91a9c7;font-size:11px;font-weight:600;letter-spacing:.3px;white-space:nowrap}th,td{padding:13px 12px;border-bottom:1px solid #25344b;vertical-align:middle}tr:last-child td{border-bottom:0}td{overflow-wrap:anywhere}td button{padding:6px 9px;min-height:34px;font-size:12px;margin:2px}.status-pill.running{background:#123a32;border-color:#2e6656;color:#89e1bf}.status-pill.offline{background:#2d2733;border-color:#584255;color:#d0a6b8}.status-pill{display:inline-block;padding:3px 8px;border-radius:6px;border:1px solid #34506c;background:#193348;color:#a7cee9;font-size:11px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;background:#0a1321;color:#b6c9e4;border:1px solid #263950;border-radius:12px;padding:14px;max-height:260px;overflow:auto;margin:14px 0 0}pre:empty{display:none}.pagination{display:flex;align-items:center;justify-content:center;gap:10px;margin-top:12px}.pagination span{font-size:12px;color:var(--muted)}.two-columns{display:grid;grid-template-columns:1fr 1fr;gap:20px}.two-columns section{min-width:0}.footnote{font-size:11px;color:#7186a3;text-align:center;padding:8px}dialog{border:1px solid #3c5578;border-radius:18px;background:#142139;color:var(--text);width:min(420px,calc(100% - 32px));padding:24px}dialog::backdrop{background:#030814c9;backdrop-filter:blur(5px)}dialog input{margin:10px 0 15px}dialog h2{font-size:18px;margin:0}.billing-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:14px}.balance-card{min-width:0;padding:15px 16px;border:1px solid #345176;border-radius:14px;background:linear-gradient(135deg,#152b49,#102039 68%,#142a39)}.balance-card span,.balance-card small{display:block;color:var(--muted);font-size:11px}.balance-card strong{display:block;color:#dcf5ff;font-size:22px;line-height:1.3;margin:7px 0;font-variant-numeric:tabular-nums}.balance-card small{overflow-wrap:anywhere}.balance-card:first-child strong{color:#91e1c6}#node{min-height:170px;padding:7px}#node option{padding:7px;border-radius:6px}section{box-shadow:0 8px 24px #02081722;transition:border-color .2s,transform .2s}section:focus-within{border-color:#385578}#dnsconfigs p{background:#0e182a;border:1px solid var(--line);border-radius:11px;padding:12px;overflow-wrap:anywhere}#dnsconfigs button{margin:9px 6px 0 0;font-size:12px;padding:7px 10px}#cfkeyfields,#alikeyfields{min-width:0}#alikeyfields:not([hidden]){display:grid;gap:14px}[hidden]{display:none!important}.metric-note{color:var(--muted);font-size:12px;margin:0}.desktop-note{color:var(--muted);font-size:12px}.step-number{font-size:12px;color:#9ec3ff;background:#203b60;border:1px solid #335a89;border-radius:7px;padding:2px 7px;margin-right:7px}
@media(min-width:900px){#deploy .grid{grid-template-columns:1fr 1fr}.hero h1{font-size:32px}}
@media(max-width:700px){html{scroll-padding-top:78px}.top-inner{padding:12px 16px}.secure{font-size:10px}.shell{padding:22px 14px calc(95px + env(safe-area-inset-bottom))}.hero{margin-bottom:20px;gap:12px}.hero h1{font-size:25px}.hero p{font-size:12px}.hero>button{min-height:40px;padding:8px 12px;white-space:nowrap}.navigation{position:fixed;bottom:0;left:0;right:0;z-index:30;margin:0;border-radius:0;border-width:1px 0 0;background:#101c30f5;backdrop-filter:blur(18px);padding:7px 8px calc(7px + env(safe-area-inset-bottom));justify-content:space-around}.navigation a{padding:9px 8px;text-align:center;font-size:12px;flex:1}.grid,.grid.three,.two-columns{grid-template-columns:1fr}.two-columns{gap:0}section{padding:18px 15px;margin-bottom:16px;border-radius:15px}.section-header h2{font-size:17px}.section-header{margin-bottom:15px}.tag{font-size:10px}.toolbar{gap:8px}.toolbar button{flex:1 1 auto}.action-row .primary{width:100%;min-height:47px}.action-row{gap:8px}.table-wrap{border:0;background:none;overflow:visible}#instances table,#instances tbody{display:block}#instances table>tr:first-child,#instances thead{display:none}#instances tr{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;background:#0d1728;border:1px solid #2b3d58;border-radius:12px;padding:15px;margin-bottom:12px}#instances tr:first-child{display:none}#instances td{display:block;border:0!important;padding:0;font-size:13px;min-width:0}#instances td:before{content:attr(data-label);display:block;color:#7f96b5;font-size:10px;margin-bottom:4px}#instances td:nth-child(3){font-weight:600}#instances td:last-child{grid-column:1/-1;padding-top:10px;border-top:1px solid #24344e!important;display:flex;flex-wrap:wrap;gap:6px}#instances td:last-child:before{display:none}#instances td button{flex:1 1 28%;margin:0;min-height:44px}#nodes th,#nodes td{padding:10px 8px;font-size:12px}.desktop-note{display:none}.pagination{gap:7px}.pagination button{padding:8px 10px;font-size:12px}.pagination span{font-size:11px}pre{max-height:220px;font-size:11px}.section-header>.primary{font-size:12px;padding:7px 11px}.brand strong{font-size:14px}}
.monitor-toolbar{margin:4px 0 12px}.monitor-toolbar label{width:min(100%,360px)}.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px}.monitor-instance{margin-top:12px;padding:15px;border:1px solid var(--line);border-radius:14px;background:#0e182a}.monitor-title{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}.monitor-title small{color:var(--muted);font-size:11px}.metric-card{min-width:0;padding:13px;border:1px solid #2a405e;border-radius:11px;background:linear-gradient(135deg,#162943,#111d31)}.metric-card span{display:block;color:var(--muted);font-size:11px}.metric-card strong{display:block;margin-top:5px;color:#d8eaff;font-size:18px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.metric-card:nth-child(4) strong{color:#81d7bd}.metric-card:nth-child(5) strong{color:#91baff}.monitor-error{padding:10px 12px;border:1px solid #70414b;border-radius:9px;background:#301c27;color:#ffb2b9;font-size:12px;overflow-wrap:anywhere}@media(max-width:620px){.monitor-title{align-items:flex-start;flex-direction:column}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.metric-card strong{font-size:16px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}button{transition:none}}
</style></head><body>
<header class="topbar"><div class="top-inner"><a class="brand" href="#overview"><span class="brand-mark">L</span><span><strong>Linode 节点管理</strong><small>CLOUD &amp; NODE CONSOLE</small></span></a><div class="toolbar"><span class="secure">● 已登录</span><button onclick="logout()">退出登录</button></div></div></header>
<main class="shell">
<div class="hero"><div><span class="eyebrow">YOUR CLOUD WORKSPACE</span><h1>服务器与节点，一处管理</h1><p>管理 Linode 实例、同步 wp2 节点，自动完成后端部署。</p></div><button onclick="load();monitor()">↻ 刷新</button></div>
<nav class="navigation" aria-label="快捷导航"><a href="/refill">补号 / 账户池</a><a href="#overview">服务器</a><a href="#create">创建实例</a><a href="#wp2">wp2 节点</a><a href="#deploy">自动部署</a><a href="#dns">设置</a><a href="#chinaprobe">国内探测</a></nav>
<section id="overview"><div class="section-header"><div><h2>Linode 账号</h2><p>先选择账号，再管理对应的服务器</p></div><span class="tag">多账号</span></div>
<label>当前账号<select id="account" onchange="changeAccount()"><option value="">全部账号（仅查看）</option></select></label><p id="accountmsg" class="message"></p>
<button onclick="openAccountManager()">管理账号</button><button onclick="openProxyPool()">代理池</button><label class="check"><input id="useproxy" type="checkbox" onchange="toggleProxy()">创建 / 开关机使用当前账号代理（不勾选直连）</label><p id="proxystatus" class="message"></p><div class="toolbar"><button id="billingbutton" onclick="queryAccountBilling()">查询余额 / 赠金</button><span class="hint">余额固定通过当前账号绑定的代理查询，未绑定时直连。</span></div><div id="billingcard" class="billing-grid"></div>
<dialog id="accountdialog"><button onclick="document.getElementById('accountdialog').close()">关闭</button><h2>管理账号</h2><div class="grid"><label>账号备注<input id="accountname" maxlength="80" placeholder="例如：日本节点账号"></label><label>Linode API Token<input id="accounttoken" type="password" placeholder="仅保存到服务器，加密存储" autocomplete="off"></label><label>新账号代理<select id="accountproxy"><option value="">直连（不绑定代理）</option></select></label></div><p class="hint">每个代理只能绑定一个账号；添加账号时只可选择未占用的池内代理，自动绑定并启用。需要新代理时先在代理池导入。</p><div class="toolbar" style="margin-top:12px"><button class="primary" id="addaccountbutton" onclick="addAccount()">添加账号</button></div><p id="accountformmsg" class="message"></p><p class="hint">删除只移除面板中保存的账号凭据，不会删除 Linode 云服务器。余额查询需要 Linode Token 的 Account: Read Only / view_account 权限。</p><div class="subpanel"><label>选择要移除的账号<select id="manageaccount"><option value="">请选择账号</option></select></label><button class="danger" id="deleteaccountbutton" onclick="deleteAccount()">删除所选账号</button></div></dialog>
<dialog id="proxypooldialog"><button onclick="document.getElementById('proxypooldialog').close()">关闭</button><h2>代理池</h2><div class="grid"><label>选择账号<select id="poolaccount" onchange="poolAccountChanged()"><option value="">请选择账号</option></select></label><label>绑定代理<select id="poolproxy" onchange="poolProxyChanged()"><option value="">直连（解除代理绑定）</option></select></label></div><div class="toolbar" style="margin-top:12px"><button class="primary" id="poolbind" onclick="bindPoolProxy()">绑定代理</button><button id="pooltestbalance" onclick="testPoolBalance()">测试余额</button></div><p class="hint">同一代理主机与端口只能绑定一个账号，停用仍保留占用。先解除原账号绑定，才能转给其他账号。绑定后可测试余额。选择直连并绑定可解除代理。</p><p id="poolmsg" class="message" aria-live="polite"></p><div id="poolbilling" class="billing-grid"></div><details class="subpanel"><summary>修改代理资料</summary><label>选择要修改的代理<select id="pooledit" onchange="selectPoolEdit()"><option value="">请选择代理</option></select></label><label>代理名称<input id="pooleditname" maxlength="80"></label><label>新代理地址（留空保留）<input id="poolediturl" type="password" autocomplete="new-password" placeholder="完整代理URL，包含需要的用户名和密码"></label><p class="hint">代理密码不回显。只改名称时地址留空；更换地址或密码时填写完整新代理 URL。修改后绑定账号自动使用新配置，仍须遵守独占绑定。</p><button id="pooleditsave" onclick="savePoolEdit()">保存修改</button><p id="pooleditmsg" class="message" aria-live="polite"></p></details><details class="subpanel"><summary>批量添加代理</summary><label>每行 名称|代理URL<textarea id="proxybatch" rows="6" placeholder="代理A|http://用户:密码@主机:端口"></textarea></label><button id="poolimport" onclick="importProxies()">保存本批代理</button></details></dialog></section>
<section id="servers"><div class="section-header"><div><h2>服务器实例</h2><p id="msg" class="message">正在加载服务器…</p></div><button onclick="load()">↻ 刷新</button></div><div id="instances" class="table-wrap"></div></section>
<section id="create"><div class="section-header"><div><h2>创建 Linode</h2><p>选择套餐与地区，确认费用后创建</p></div><span class="tag">新实例</span></div><div class="toolbar" style="margin-bottom:16px"><button onclick="catalogs()">加载地区、套餐和系统</button><span class="desktop-note">选项来自当前 Linode 账号</span></div><div class="grid"><label>Linode 名称（仅支持英文字符）<input id="createlabel" placeholder="例如：jp-node-01" maxlength="64"><span class="hint">Linode 不接受中文名称；用英文、数字、短横线、下划线或点。</span></label><label>地区<select id="createregion"><option value="">请先加载选项</option></select></label><label>套餐<select id="createtype"><option value="">请先加载选项</option></select></label><label>系统镜像<select id="createimage"><option value="">请先加载选项</option></select></label><label class="span-all">Root 密码<div class="toolbar"><input id="createpass" type="password" autocomplete="new-password" placeholder="至少 12 位，创建后加密保存"><button type="button" onclick="generateRootPassword()">生成随机密码</button></div><span class="hint">使用安全随机源生成 24 位密码，创建后由面板加密保存。</span></label></div><div class="action-row"><label class="check"><input id="openallports" type="checkbox" checked>新实例默认放行全部端口</label><label class="check"><input id="createaliyuncheck" type="checkbox" checked>开机后阿里云检查 TCP/22（仅检查）</label><button class="primary" id="createbutton" onclick="createInstance()">创建并开机</button></div><p id="createmsg" class="message"></p><pre id="createbootlog" aria-live="polite">创建后的开机检查日志将显示在这里。</pre></section>
<section id="wp2"><div class="section-header"><div><h2>wp2 节点</h2><p>连接管理员账号，同步全部节点</p></div><button onclick="nodes()">↻ 同步节点</button></div><p id="wp2connection" class="message"></p><details class="subpanel"><summary>连接或更换 wp2 账号</summary><div class="grid"><label>管理员邮箱<input id="wp2email" type="email" autocomplete="username" placeholder="admin@example.com"></label><label>管理员密码<input id="wp2password" type="password" autocomplete="off" placeholder="密码仅用于本次登录"></label><label class="span-all">两步动态码（如启用）<input id="wp2code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="6 位动态码"></label></div><div class="toolbar" style="margin-top:14px"><button class="primary" id="wp2connect" onclick="connectWP2()">连接 wp2</button><button class="danger" onclick="disconnectWP2()">断开连接</button></div><p class="hint">登录会话加密保存在管理机，密码不保存。</p></details><p id="nodehint" class="message">正在加载节点…</p><details class="reveal"><summary>浏览节点列表 · 搜索 / 分页</summary><input id="nodesearch" placeholder="搜索节点名称或 ID" aria-label="搜索节点" oninput="nodePage=0;renderNodes()"><div id="nodes" style="margin-top:12px"></div><div class="pagination"><button id="nodesprev" onclick="nodePage--;renderNodes()">上一页</button><span id="nodespage"></span><button id="nodesnext" onclick="nodePage++;renderNodes()">下一页</button></div></details></section>
<section id="deploy"><div class="section-header"><div><h2>自动安装后端</h2><p>选择实例和节点，支持先安装 Hysteria2，之后继续添加 VLESS 等节点</p></div><span class="tag">多节点共用后端</span></div><p id="installaccount" class="message">请先选择 Linode 账号</p><div class="grid" style="margin-top:14px"><label><span><span class="step-number">1</span>安装到哪台服务器</span><select id="instance" onchange="updateDNSTarget()"><option value="">请先选择账号并加载服务器</option></select></label><label><span><span class="step-number">2</span>搜索并多选 wp2 节点</span><input id="nodefilter" type="search" placeholder="按名称、ID 或协议筛选" oninput="filterInstallNodes()"><select id="node" multiple size="7" aria-label="可多选 wp2 节点" onchange="rememberInstallNodes();updateDNSTarget()"><option value="">请先同步 wp2 节点</option></select><span id="selectednodes" class="hint">增加节点会保留已安装节点及 Hysteria2 端口跳跃规则。</span></label></div><div class="action-row"><span class="desktop-note">DNS 自动解析按下方启用的域名配置匹配</span><div class="toolbar"><button onclick="backendLogs()" id="backendlogbutton">查看后端日志</button><button class="primary" id="installbutton" onclick="install('add')">增加所选节点</button><button id="replacebutton" onclick="install('replace')">重装所选节点</button></div></div><pre id="joblog" aria-live="polite"></pre><button id="ipcleanup" hidden onclick="cleanupIPChange()">清理残留临时实例</button><details class="subpanel"><summary>最近换 IP 任务</summary><button onclick="loadIPChanges()">刷新任务</button><div id="ipchanges"></div></details><details class="subpanel"><summary>查询历史任务</summary><div class="toolbar"><input id="job" placeholder="任务 ID" aria-label="任务 ID"><button onclick="job()">查询任务</button></div></details></section>
<section id="dns"><div class="section-header"><div><h2>DNS 自动解析与证书</h2><p>配置一次密钥，安装时按节点域名自动匹配</p></div><span class="tag">加密保存</span></div><p id="dnstarget" class="message">请选择安装目标服务器，DNS 将指向该实例公网 IP。</p><div id="dnsconfigs"></div><p id="dnsmsg" class="message"></p><details class="subpanel"><summary>添加 DNS 域名与密钥</summary><div class="grid"><label>DNS 服务商<select id="dnsprovider" onchange="dnsFields()"><option value="cloudflare">Cloudflare</option><option value="alidns">阿里云 DNS</option></select></label><label>托管域名<input id="dnszone" placeholder="填写 Key 后可自动读取，或手动填写"></label><div class="span-all"><div class="toolbar"><button id="dnsdiscover" onclick="discoverDNS()">读取托管域名并匹配节点</button><select id="dnszones" aria-label="已读取的托管域名" onchange="document.getElementById('dnszone').value=this.value"><option value="">先填写 Key，再读取域名</option></select></div></div><span id="cfkeyfields" class="span-all"><label>Cloudflare API Token<input id="dnstoken" type="password" autocomplete="off" placeholder="需要 Zone Read / DNS Edit 权限"></label></span><span id="alikeyfields" class="span-all" hidden><label>阿里云 AccessKey ID<input id="dnsaccessid" type="password" autocomplete="off" placeholder="RAM AccessKey ID"></label><label>阿里云 AccessKey Secret<input id="dnssecret" type="password" autocomplete="off" placeholder="RAM AccessKey Secret"></label></span></div><div class="action-row"><label class="check"><input id="dnsenabled" type="checkbox" checked>安装时自动更新 DNS</label><button class="primary" onclick="saveDNS()">加密保存 DNS 配置</button></div><p class="hint">只更新节点子域名 A/AAAA；Cloudflare 使用灰云。根域名、面板地址和 CNAME 不自动修改。</p></details></section>
<section id="chinaprobe"><div class="section-header"><div><h2>国内 TCP 探测</h2><p>开机后自动检查 IP，也可在换 IP 时验证候选地址</p></div><span class="tag">加密保存</span></div><p id="chinaprobestatus" class="message">正在读取探测配置…</p><div class="subpanel"><div class="grid"><label class="check"><input id="bootipcheck" type="checkbox" checked>开机后自动检测 IP</label><label>开机检查 TCP 端口<input id="bootipport" type="number" min="1" max="65535" value="22"></label><label class="check"><input id="bootipreplace" type="checkbox" checked>国内探测失败时自动换 IP</label></div><div class="toolbar" style="margin-top:12px"><button class="primary" onclick="saveChinaBootSettings()">保存开机检测设置</button></div><p class="hint">创建并开机、手动开机或重启后执行。必须先确认面板本机能连该端口，避免把服务未启动误判成 IP 被墙；自动换 IP 时，新 IP 也必须通过国内检查才释放旧 IP。IPTrace 每次探测 4 点。</p></div><div class="grid"><label>阿里云探测机公网 IPv4<input id="cnprobehost" inputmode="decimal" placeholder="例如 1.2.3.4"></label><label>SSH 端口<input id="cnprobeport" type="number" min="1" max="65535" value="22"></label><label>SSH 用户<input id="cnprobeuser" value="root" autocomplete="username"></label><label>SSH 密码<input id="cnprobepassword" type="password" autocomplete="new-password" placeholder="留空保留已保存密码"></label></div><div class="toolbar" style="margin-top:12px"><button class="primary" onclick="saveDomesticProbe()">测试 SSH 并启用阿里云探测</button><button onclick="selectChinaProbe('aliyun')">切换到阿里云探测</button><button class="danger" onclick="removeDomesticProbe()">删除 SSH 配置</button></div><p class="hint">面板会 SSH 到这台机器，运行 Bash TCP 连接检查。SSH 主机密钥首次连接时自动记录，之后校验不变。</p><div class="subpanel"><label>IPTrace API Key<input id="iptracekey" type="password" autocomplete="off" placeholder="保存后加密；留空保留现有 Key"></label><div class="toolbar" style="margin-top:12px"><button class="primary" onclick="saveIPTraceProbe()">验证 Key 并启用 IPTrace</button><button onclick="selectChinaProbe('iptrace')">切换到 IPTrace</button><button class="danger" onclick="removeIPTraceProbe()">删除 IPTrace Key</button></div><p class="hint">IPTrace 使用 country=CN 的 TCP 探测节点。按其文档，每次中国节点 TCP 探测固定消耗 4 点；保存 Key 只做账户验证，不扣检测点数。</p></div><p id="chinaprobemsg" class="message"></p></section>
<section id="telegram"><div class="section-header"><div><h2>Telegram 提醒</h2><p>直接配置机器人，接收监控异常与恢复通知</p></div><span class="tag">消息通知</span></div><p id="tgstatus" class="message"></p><details class="subpanel"><summary>设置机器人与接收聊天</summary><div class="grid"><label>Bot Token<input id="tgtoken" type="password" autocomplete="off" placeholder="由 BotFather 获取；留空保留已保存 Token"></label><label>Chat ID<input id="tgchat" placeholder="个人 ID、群组负数 ID 或 @频道用户名"></label></div><div class="action-row"><label class="check"><input id="tgenabled" type="checkbox" checked>启用 Telegram 提醒</label><button class="primary" onclick="saveTelegram()">加密保存</button></div><p class="hint">个人聊天请先向机器人发送 /start；群组或频道需允许机器人发消息。告警依赖资源监控运行。</p></details><div class="toolbar" style="margin-top:14px"><button id="tgtest" onclick="testTelegram()">发送测试消息</button><button class="danger" onclick="removeTelegram()">移除网页配置</button></div><p id="tgmsg" class="message"></p></section><section id="monitor"><div class="section-header"><div><h2>资源监控</h2><p>CPU / 内存 / 磁盘与网卡流量 · 速率为实时采样，累计流量为系统网卡计数</p></div><span class="tag">SSH 采样</span></div><div class="toolbar monitor-toolbar"><label>实时采样实例<select id="monitorinstance" aria-label="实时采样实例"><option value="">请先选择 Linode 账号</option></select></label><button onclick="monitor()">显示监控</button><button class="primary" id="monitorrefresh" onclick="refreshMonitor()">立即采样</button></div><p id="monitorhint" class="message" aria-live="polite"></p><div id="metrics" class="metric-grid"></div></section>
<p class="footnote">Linode Node Manager · 通过 HTTPS 访问 · 凭据加密存储</p>
</main>
<dialog id="ipchangedialog"><h2>保留原机 · 更换公网 IPv4</h2><p id="ipsummary" class="message"></p><p class="hint">直接在原机上申请第二个 IPv4；候选地址通过面板与所选国内探测后才释放旧地址。Linode 账号需要允许额外 IPv4，额外公网地址可能产生费用；停机期间申请并切换，完成后恢复原机。</p><label style="margin-top:12px">DDNS 域名绑定（已绑定的服务器自动选择）<select id="ipnode"></select></label><label style="margin-top:12px">新 IP TCP 检查端口<input id="ipcheckport" type="number" min="1" max="65535" value="22" inputmode="numeric"></label><p id="cnprobehint" class="hint">请先在“国内探测”设置中配置一种探测方式。</p><label class="check"><input id="ipcheckchinaoriginal" type="checkbox" checked>先检测旧 IP；若国内可达则取消更换</label><p class="hint">只执行当前选中的一种国内探测；IPTrace 每次检测 4 点，若勾选旧 IP 检查，本次换 IP 最多消耗 8 点。可用 tcp.ping.pe 手动复核。</p><button type="button" onclick="openChinaTCPCheck()">打开 tcp.ping.pe 检查当前 IP</button><p class="hint">换 IP 后自动将绑定节点的连接域名解析更新到新 IP，wp2 节点仍使用原域名。首次使用需选择该服务器对应的节点以确定域名；已有绑定时自动使用。若账号 IPv4 配额不允许增加地址，会保留旧 IP 并停止。</p><label class="check"><input id="ipbilling" type="checkbox">我确认额外 IPv4 可能产生的费用及短暂停机</label><p id="iperror" class="message"></p><div class="toolbar"><button class="primary" id="ipconfirm" onclick="startIPChange()">确认换 IP</button><button onclick="document.getElementById('ipchangedialog').close()">取消</button></div></dialog>
<dialog id="passworddialog" onclose="document.getElementById('savedpassword').value=''"><h2>Root 密码</h2><p class="hint">仅在此处显示，关闭后清空</p><input id="savedpassword" type="text" readonly autocomplete="off" aria-label="已保存的 Root 密码"><button onclick="document.getElementById('passworddialog').close()">关闭并清除</button></dialog><dialog id="savepassworddialog" onclose="document.getElementById('rootpassinput').value=''"><h2>保存现有实例密码</h2><p class="hint">只加密保存到本面板，不会发送到 Linode 修改服务器密码。保存后可用于 SSH 监控和自动部署。</p><label>Root 密码<input id="rootpassinput" type="password" minlength="12" maxlength="128" autocomplete="new-password" placeholder="输入现有服务器 Root 密码"></label><p id="rootpassmsg" class="message"></p><div class="toolbar"><button class="primary" id="rootpasssave" onclick="saveExistingPassword()">加密保存</button><button onclick="document.getElementById('savepassworddialog').close()">取消</button></div></dialog>
<script>async function api(path,options={}){if(path.startsWith('/monitor/refresh')||path==='/instances'||path.startsWith('/instances/')||path==='/deployments/install'||path.startsWith('/catalog/')||path==='/linode/proxy'){let a=document.getElementById('account').value;if(a&&!path.includes('account_id='))path+=(path.includes('?')?'&':'?')+'account_id='+encodeURIComponent(a);if(document.getElementById('useproxy').checked&&!path.includes('use_proxy=')&&path!='/linode/proxy'&&!path.startsWith('/linode/proxy?'))path+=(path.includes('?')?'&':'?')+'use_proxy=true'}let r=await fetch('/api'+path,{...options,credentials:'same-origin',headers:{'Content-Type':'application/json'}});if(r.status===401&&r.headers?.get('X-LNM-Auth-Required')==='true'){globalThis.location?.assign('/login');throw Error('登录已过期，请重新登录')}let j=await r.json();if(!r.ok)throw Error(j.error||r.status);return j}async function loadAccounts(){let box=document.getElementById('account'),old=box.value;try{let data=await api('/accounts');box.replaceChildren();let all=document.createElement('option');all.value='';all.textContent='全部账号（仅查看）';box.appendChild(all);for(let a of data.accounts){let o=document.createElement('option');o.value=a.id;o.textContent=a.name;box.appendChild(o)}box.value=old&&Array.from(box.options).some(o=>o.value===old)?old:(data.accounts.length===1?data.accounts[0].id:'');fillManagedAccounts(data.accounts);document.getElementById('accountmsg').textContent='已加载 '+data.accounts.length+' 个账号'}catch(e){document.getElementById('accountmsg').textContent=e.message}}
async function logout(){await api('/logout',{method:'POST',body:'{}'});globalThis.location?.assign('/login')}
async function openAccountManager(){document.getElementById('accountdialog').showModal();document.getElementById('accountformmsg').textContent='';try{await loadAccounts();await loadProxyPool()}catch(e){document.getElementById('accountformmsg').textContent='代理池加载失败：'+e.message}}
async function addAccount(){const button=document.getElementById('addaccountbutton'),message=document.getElementById('accountformmsg'),name=document.getElementById('accountname').value.trim(),token=document.getElementById('accounttoken').value,proxyID=document.getElementById('accountproxy').value;if(button.disabled)return;if(!name||token.length<20){message.textContent='请输入账号备注和有效 Token';return}button.disabled=true;let created=null;try{created=await api('/accounts',{method:'POST',body:JSON.stringify({name,token,proxy_id:proxyID})});document.getElementById('accounttoken').value='';await loadAccounts();await loadProxyPool();document.getElementById('account').value=created.id;await proxyStatus();await load();message.textContent='已添加：'+created.name+(proxyID?'；池内代理已绑定并启用，可测试余额。':'；使用直连，可测试余额。');document.getElementById('accountmsg').textContent=message.textContent}catch(e){message.textContent=(created?'账号已添加，请勿重复添加；加载失败：':'')+e.message}finally{button.disabled=false}}

function fillManagedAccounts(accounts){const select=document.getElementById('manageaccount'),previous=select.value;select.replaceChildren();const none=document.createElement('option');none.value='';none.textContent='请选择要移除的账号';select.appendChild(none);for(const account of accounts){const option=document.createElement('option');option.value=account.id;option.textContent=account.name;select.appendChild(option)}select.value=accounts.some(a=>a.id===previous)?previous:(accounts.some(a=>a.id===document.getElementById('account').value)?document.getElementById('account').value:'')}
async function deleteAccount(){const select=document.getElementById('manageaccount'),id=select.value,button=document.getElementById('deleteaccountbutton'),message=document.getElementById('accountformmsg');if(button.disabled)return;if(!id){message.textContent='请从下拉框选择要移除的账号';return}const label=select.selectedOptions[0]?.textContent||id;if(!confirm('删除账号“'+label+'”的面板凭据并解除代理绑定？不会删除 Linode 云服务器。'))return;button.disabled=true;let deleted=false;try{await api('/accounts/'+encodeURIComponent(id),{method:'DELETE'});deleted=true;if(document.getElementById('account').value===id)document.getElementById('billingcard').replaceChildren();await loadAccounts();await loadProxyPool();await proxyStatus();await Promise.all([load(),monitor()]);message.textContent='已移除账号：'+label+'，代理绑定已释放。'}catch(e){message.textContent=(deleted?'账号已移除，刷新失败：':'')+e.message}finally{button.disabled=false}}

function renderBilling(data,box){const amount=value=>Number(value||0).toLocaleString('en-US',{style:'currency',currency:'USD'});const addCard=(title,value,detail)=>{const card=document.createElement('div');card.className='balance-card';const h=document.createElement('span');h.textContent=title;const strong=document.createElement('strong');strong.textContent=value;const note=document.createElement('small');note.textContent=detail||'';card.appendChild(h);card.appendChild(strong);card.appendChild(note);box.appendChild(card)};addCard('账户余额',amount(data.balance),'美元 USD · Linode account balance');addCard('本月预计费用',amount(data.balance_uninvoiced),'已产生但尚未结算的估算账单');for(const promo of data.active_promotions||[]){addCard(promo.summary||'活动赠金剩余',amount(promo.credit_remaining),'本月可用 '+amount(promo.this_month_credit_remaining)+(promo.credit_monthly_cap?' / 月度上限 '+amount(promo.credit_monthly_cap):'')+(promo.expire_dt?' · 到期 '+promo.expire_dt.slice(0,10):''))}}
function setAccountMessage(text){for(const id of ['accountmsg','accountformmsg'])document.getElementById(id).textContent=text}
let billingSequence=0,activeBillingAccount=null;
async function queryAccountBilling(){const id=document.getElementById('account').value,box=document.getElementById('billingcard'),button=document.getElementById('billingbutton');if(id&&activeBillingAccount===id)return;const sequence=++billingSequence;activeBillingAccount=id||null;box.replaceChildren();if(!id){button.disabled=false;setAccountMessage('请先从账号下拉框选择一个 Linode 账号，再查询余额。');return}button.disabled=true;setAccountMessage('正在按账号绑定读取余额与活动赠金…');try{const data=await api('/accounts/'+encodeURIComponent(id)+'/billing');if(sequence!==billingSequence||document.getElementById('account').value!==id)return;renderBilling(data,box);setAccountMessage('余额与赠金已更新：'+accountLabel(id)+'；已使用该账号的绑定连接。')}catch(e){if(sequence===billingSequence&&document.getElementById('account').value===id)setAccountMessage(e.message)}finally{if(sequence===billingSequence){activeBillingAccount=null;button.disabled=false}}}

const esc=x=>String(x??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));async function power(id,action){if(!document.getElementById('account').value){document.getElementById('msg').textContent='请先选择目标账号，不能在全部账号视图操作';return}if(!confirm('确认对实例 '+id+' 执行 '+action+'？'))return;try{const result=await api('/instances/'+id+'/'+action,{method:'POST'});await load();if(result.boot_job_id){document.getElementById('job').value=result.boot_job_id;watchJob(result.boot_job_id)}}catch(e){document.getElementById('msg').textContent=e.message}}const show=(id,x)=>document.getElementById(id).textContent=JSON.stringify(x,null,2);async function load(){const selectedAccount=document.getElementById('account').value;const target=document.getElementById('instance'),previous=installationAccount===selectedAccount?target.value:'';installationAccount='';target.replaceChildren();document.getElementById('instances').textContent='正在加载当前账号服务器…';updateDNSTarget();try{let d=await api('/instances');if(document.getElementById('account').value!==selectedAccount)return;updateInstallTargets(d.instances,selectedAccount,previous);updateMonitorInstances(d.instances,selectedAccount);document.getElementById('instances').innerHTML='<table><tr><th>Linode 账号</th><th>ID</th><th>名称</th><th>状态</th><th>IP 地址</th><th>地区 / 套餐</th><th>操作</th></tr>'+d.instances.map((i,index)=>'<tr><td data-label="账号">'+esc(accountLabel(i.account_id))+'</td><td data-label="实例 ID">'+Number(i.id)+'</td><td data-label="名称">'+esc(i.label)+'</td><td data-label="状态"><span class="status-pill '+esc(i.status)+'">'+esc(i.status)+'</span></td><td data-label="IP 地址">'+esc((i.ipv4||[]).join(', ')||'分配中')+(i.ipv6?'<br>'+esc(i.ipv6):'')+'</td><td data-label="地区 / 套餐">'+esc(i.region)+'<br>'+esc(i.type)+'</td><td><button '+(!selectedAccount||i.status!=='offline'?'disabled':'')+' onclick="power('+Number(i.id)+',\'boot\')">开机</button><button '+(!selectedAccount||i.status!=='running'?'disabled':'')+' onclick="power('+Number(i.id)+',\'shutdown\')">关机</button><button '+(!selectedAccount||i.status!=='running'?'disabled':'')+' onclick="power('+Number(i.id)+',\'reboot\')">重启</button><button data-action="password" data-index="'+index+'" '+(i.password_saved?'':'disabled')+'>查看密码</button><button data-action="setpassword" data-index="'+index+'">'+(i.password_saved?'修改 SSH 密码':'保存 SSH 密码')+'</button><button data-action="changeip" data-index="'+index+'">更换 IPv4</button><button class="danger" data-action="delete" data-index="'+index+'">删除实例</button></td></tr>').join('')+'</table>';document.getElementById('instances').querySelectorAll('[data-action]').forEach(button=>button.onclick=()=>instanceOperation(d.instances[Number(button.dataset.index)],button.dataset.action));document.getElementById('msg').textContent=d.instances.length?'已加载 '+d.instances.length+' 台；选择目标账号后可使用每行的开机、关机、重启按钮':'当前账号没有实例，请检查 Linode API Token 或选择其他账号'}catch(e){document.getElementById('msg').textContent='服务器列表加载失败：'+e.message}}async function nodes(){document.getElementById('nodehint').textContent='正在同步 wp2 节点…';try{let d=await api('/wp2/nodes');nodeCache=d.nodes||[];nodePage=0;filterInstallNodes();renderNodes();document.getElementById('nodehint').textContent=nodeCache.length?'已同步 '+nodeCache.length+' 个节点；可搜索并多选安装':(d.warning||'wp2 接口返回 0 个节点，请检查 wp2 节点配置与 API 访问权限')}catch(e){nodeCache=[];nodePage=0;selectedInstallNodeIDs.clear();renderNodes();filterInstallNodes();document.getElementById('nodehint').textContent='wp2 同步失败：'+e.message}}function updateMonitorInstances(instances,account){const select=document.getElementById('monitorinstance'),previous=select.value;select.replaceChildren();const available=account?instances.filter(i=>i.account_id===account):[];if(!available.length){const option=document.createElement('option');option.value='';option.textContent=account?'该账号没有可采样实例':'请先选择 Linode 账号';select.appendChild(option);select.disabled=true;return}select.disabled=false;for(const instance of available){const option=document.createElement('option');option.value=String(instance.id);option.textContent=(instance.label||'Linode')+' (#'+instance.id+') · '+instance.status;select.appendChild(option)}select.value=available.some(i=>String(i.id)===previous)?previous:String(available.find(i=>i.status==='running')?.id||available[0].id)}
function humanBytes(value){const n=Number(value)||0;if(n<1024)return n.toFixed(0)+' B';const units=['KB','MB','GB','TB','PB'];let amount=n/1024,index=0;while(amount>=1024&&index<units.length-1){amount/=1024;index++}return amount.toFixed(2)+' '+units[index]}
function renderMonitor(items){const root=document.getElementById('metrics');root.replaceChildren();if(!items.length){document.getElementById('monitorhint').textContent='暂无监控快照。选择账号后点“立即采样”；SSH 需要实例已开机并配置好登录密钥。';return}for(const item of items){const panel=document.createElement('div');panel.className='monitor-instance';const heading=document.createElement('div');heading.className='monitor-title';const title=document.createElement('strong');title.textContent=(item.label||'Linode')+' (#'+item.id+')';const stamp=document.createElement('small');stamp.textContent=item.updated_at?'更新于 '+new Date(item.updated_at).toLocaleString():'等待采样';heading.appendChild(title);heading.appendChild(stamp);panel.appendChild(heading);if(item.monitor_error){const error=document.createElement('p');error.className='monitor-error';error.textContent='采样失败：'+item.monitor_error;panel.appendChild(error);root.appendChild(panel);continue}const cards=[['CPU',Number(item.cpu||0).toFixed(1)+'%'],['内存',Number(item.memory||0).toFixed(1)+'%'],['磁盘',Number(item.disk||0).toFixed(1)+'%'],['下载速率',Number(item.download_mbps||0).toFixed(3)+' Mbps'],['上传速率',Number(item.upload_mbps||0).toFixed(3)+' Mbps'],['累计下载',humanBytes(item.download_bytes)],['累计上传',humanBytes(item.upload_bytes)],['后端服务',item.service||'未知'],['网卡',item.network_interface||'未知']];const grid=document.createElement('div');grid.className='metric-grid';for(const [name,value] of cards){const card=document.createElement('div');card.className='metric-card';const label=document.createElement('span');label.textContent=name;const strong=document.createElement('strong');strong.textContent=value;card.appendChild(label);card.appendChild(strong);grid.appendChild(card)}panel.appendChild(grid);root.appendChild(panel)}document.getElementById('monitorhint').textContent='速率为本次 SSH 采样窗口内的瞬时值；累计值从系统启动或网卡计数器重置开始，不等同于 Linode 月度流量账单。'}
async function monitor(){try{const d=await api('/monitor'),account=document.getElementById('account').value;renderMonitor(account?(d.instances||[]).filter(i=>i.account_id===account):[])}catch(e){document.getElementById('monitorhint').textContent='读取监控失败：'+e.message}}
async function refreshMonitor(){const button=document.getElementById('monitorrefresh'),account=document.getElementById('account').value,id=document.getElementById('monitorinstance').value;if(!account){document.getElementById('monitorhint').textContent='请先选择 Linode 账号。';return}if(!id){document.getElementById('monitorhint').textContent='该账号没有可采样实例。';return}if(button.disabled)return;button.disabled=true;document.getElementById('monitorhint').textContent='正在通过 SSH 采样，通常需要数秒…';try{const item=await api('/monitor/refresh?instance_id='+encodeURIComponent(id));renderMonitor([item])}catch(e){document.getElementById('monitorhint').textContent='立即采样失败：'+e.message}finally{button.disabled=false}}async function install(operation='add'){
 const button=document.getElementById('installbutton'),account=document.getElementById('account'),instance=document.getElementById('instance'),node=document.getElementById('node');
 if(button.disabled)return;
 if(!account.value){show('joblog','请先选择目标 Linode 账号');return}
 if(installationAccount!==account.value||!Number.isInteger(Number(instance.value))||Number(instance.value)<=0){show('joblog','请选择该账号下运行中的 Linode 服务器');return}
 const targetIDs=Array.from(selectedInstallNodeIDs).map(Number).filter(id=>Number.isInteger(id)&&id>0);
 if(!targetIDs.length){show('joblog','请先搜索并选择一个或多个 wp2 节点');return}
 const selectedLabels=nodeCache.filter(n=>targetIDs.includes(Number(n.id))).map(n=>String(n.name||'节点')+' (#'+n.id+')').join('、');
 const adding=operation==='add';
 const summary=adding?'将新增所选节点，并保留服务器上已有节点和 Hysteria2 端口跳跃规则。':'将重装所选节点，其余已安装节点及其端口跳跃规则会保留。';
 if(!confirm((adding?'确认增加节点？':'确认重装所选节点？')+'\nLinode 账号：'+accountLabel(account.value)+'\n服务器：'+instance.selectedOptions[0].textContent+'\nwp2 节点（'+targetIDs.length+'个）：'+selectedLabels+'\n'+summary+'服务可能会短暂重启；如启用 DNS 配置，会逐个更新并验证所选节点的解析。'))return;
 button.disabled=true;document.getElementById('replacebutton').disabled=true;
 try{const result=await api('/deployments/install',{method:'POST',body:JSON.stringify({instance_id:Number(instance.value),mode:'node',operation,target_ids:targetIDs,target_id:targetIDs[0]})});document.getElementById('job').value=result.job_id;show('joblog',result);watchJob(result.job_id)}catch(e){button.disabled=false;document.getElementById('replacebutton').disabled=false;show('joblog',e.message)}
}
async function job(){try{showJob(await api('/deployments/'+encodeURIComponent(document.getElementById('job').value)))}catch(e){show('joblog',e.message)}}

let rootPasswordTarget=null;
async function saveExistingPassword(){const button=document.getElementById('rootpasssave'),input=document.getElementById('rootpassinput'),message=document.getElementById('rootpassmsg');if(!rootPasswordTarget){message.textContent='请先选择实例';return}if(document.getElementById('account').value!==rootPasswordTarget.account_id){message.textContent='账号选择已改变，请关闭窗口后重新选择实例';return}if(input.value.length<12||input.value.length>128){message.textContent='Root 密码长度必须为 12 至 128 个字符';return}if(button.disabled)return;button.disabled=true;message.textContent='正在验证实例并加密保存…';try{await api('/instances/'+rootPasswordTarget.id+'/password?account_id='+encodeURIComponent(rootPasswordTarget.account_id),{method:'PUT',body:JSON.stringify({root_pass:input.value})});input.value='';document.getElementById('savepassworddialog').close();document.getElementById('msg').textContent='SSH 密码已加密保存，可立即刷新监控。';await load();await refreshMonitor()}catch(e){message.textContent=e.message}finally{button.disabled=false}}
async function instanceOperation(instance,action){
 if(action==='changeip'){await openIPChange(instance);return}
 if(action==='setpassword'){rootPasswordTarget=instance;document.getElementById('rootpassmsg').textContent='为 '+instance.label+' (#'+instance.id+') 保存现有密码';document.getElementById('rootpassinput').value='';document.getElementById('savepassworddialog').showModal();return}
 const message=document.getElementById('msg');
 const suffix='?account_id='+encodeURIComponent(instance.account_id);
 try{
  if(action==='password'){
   const result=await api('/instances/'+instance.id+'/password'+suffix);
   const dialog=document.getElementById('passworddialog');document.getElementById('savedpassword').value=result.root_pass;dialog.showModal();return;
  }
  const typed=prompt('永久删除实例 '+instance.label+' (#'+instance.id+')？磁盘数据将丢失。\n账号：'+instance.account_id+'\nIP：'+(instance.ipv4||[]).join(', ')+'\n请输入实例 ID 确认：');
  if(typed!==String(instance.id))return;
  const result=await api('/instances/'+instance.id+suffix+'&confirm_id='+instance.id,{method:'DELETE'});
  await load();message.textContent=result.warning||'实例已删除：'+instance.id;
 }catch(e){message.textContent=e.message}
}
let catalogAccount='';
async function catalogs(){
 const account=document.getElementById('account').value;
 if(!account){document.getElementById('createmsg').textContent='请先选择目标 Linode 账号';return}
 catalogAccount='';
 try{
  const [regions,types,images]=await Promise.all(['regions','types','images'].map(k=>api('/catalog/'+k)));
  if(document.getElementById('account').value!==account)return;
  for(const [id,items,label] of [
   ['createregion',regions.data,x=>x.label+' ('+x.id+')'],
   ['createtype',types.data,x=>x.label+' — USD '+x.price?.monthly+'/月，'+x.price?.hourly+'/小时（地区价格以 Linode 为准）'],
   ['createimage',images.data.filter(x=>!x.deprecated),x=>x.label+' ('+x.id+')']]){
   const select=document.getElementById(id);select.replaceChildren();
   const empty=document.createElement('option');empty.value='';empty.textContent='请选择';select.appendChild(empty);
   for(const item of items){const option=document.createElement('option');option.value=item.id;option.textContent=label(item);select.appendChild(option)}
  }
  catalogAccount=account;document.getElementById('createmsg').textContent='选项已加载；请确认套餐费用和地区后创建';
 }catch(e){document.getElementById('createmsg').textContent=e.message}
}
function generateRootPassword(){const pools=['ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#$%^&*()-_=+'];const pick=pool=>pool[crypto.getRandomValues(new Uint32Array(1))[0]%pool.length];const chars=pools.map(pick),all=pools.join('');while(chars.length<24)chars.push(pick(all));for(let i=chars.length-1;i>0;i--){const j=crypto.getRandomValues(new Uint32Array(1))[0]%(i+1);[chars[i],chars[j]]=[chars[j],chars[i]]}document.getElementById('createpass').value=chars.join('');document.getElementById('createmsg').textContent='已生成安全随机 Root 密码。创建成功后可在服务器列表点击“查看密码”。'}
async function createInstance(){
 const account=document.getElementById('account');
 const region=document.getElementById('createregion'),type=document.getElementById('createtype'),image=document.getElementById('createimage');
 const password=document.getElementById('createpass'),button=document.getElementById('createbutton');
 const label=document.getElementById('createlabel').value.trim();
 const message=document.getElementById('createmsg');
 if(!account.value||catalogAccount!==account.value){message.textContent='请先选择账号并重新加载创建选项';return}
 if(!/^[a-zA-Z](?!.*(?:--|__|\.\.))[a-zA-Z0-9._-]{1,62}[a-zA-Z0-9]$/.test(label)){message.textContent='Linode 名称不能包含中文；请用英文字母开头、字母或数字结尾，并只使用英文、数字、-、_、.（3 至 64 位）';return}
 if(!region.value||!type.value||!image.value||password.value.length<12){message.textContent='请填写地区、套餐、系统和至少12位 Root 密码';return}
 if(button.disabled)return;
 if(!confirm('确认创建收费服务器？\n账号：'+account.selectedOptions[0].textContent+'\n名称：'+label+'\n地区：'+region.selectedOptions[0].textContent+'\nAPI 连接：'+(document.getElementById('useproxy').checked?'使用代理':'直连')+'\n套餐：'+type.selectedOptions[0].textContent+'\n系统：'+image.selectedOptions[0].textContent+'\n新实例端口：'+(document.getElementById('openallports').checked?'全部放行':'使用账号默认云防火墙')))return;
 button.disabled=true;account.disabled=true;message.textContent='正在提交创建请求，请勿重复操作…';
 try{
  const created=await api('/instances',{method:'POST',body:JSON.stringify({label,region:region.value,type:type.value,image:image.value,root_pass:password.value,confirm:true,open_all_ports:document.getElementById('openallports').checked,aliyun_check:document.getElementById('createaliyuncheck').checked})});
  message.textContent='创建成功，实例 ID：'+created.id+'，状态：'+created.status+'。'+(created.password_saved?'Root 密码已加密保存。':created.warning||'Root 密码未保存，请保管原密码。')+' 请刷新查看 IP 和启动进度。';
  await load();if(created.boot_job_id){document.getElementById('job').value=created.boot_job_id;watchCreateBoot(created.boot_job_id)}
 }catch(e){message.textContent=e.message}
 finally{password.value='';button.disabled=false;account.disabled=false}
}

async function watchCreateBoot(id){const output=document.getElementById('createbootlog');output.textContent='等待开机检查… 任务 '+id;try{while(true){const result=await api('/deployments/'+encodeURIComponent(id));output.textContent='任务 '+id+' · '+result.status+'\n'+(result.log||'等待执行…');if(['success','failed','partial','interrupted'].includes(result.status))break;await new Promise(resolve=>setTimeout(resolve,2500))}}catch(e){output.textContent+='\n读取日志失败：'+e.message}}

async function wp2Connection(){try{const status=await api('/wp2/session');document.getElementById('wp2connection').textContent=status.message||(status.connected?'已保存 wp2 登录会话；同步节点时验证会话是否有效':'未连接管理员账号，当前使用 muKey 节点接口')}catch(e){document.getElementById('wp2connection').textContent=e.message}}
async function connectWP2(){
 const button=document.getElementById('wp2connect'),password=document.getElementById('wp2password'),code=document.getElementById('wp2code'),message=document.getElementById('wp2connection');
 if(button.disabled)return;button.disabled=true;message.textContent='正在登录并验证管理员权限…';
 try{await api('/wp2/session',{method:'POST',body:JSON.stringify({email:document.getElementById('wp2email').value,password:password.value,code:code.value})});message.textContent='wp2 已连接';await nodes()}catch(e){message.textContent=e.message}finally{password.value='';code.value='';button.disabled=false}
}
async function disconnectWP2(){try{await api('/wp2/session',{method:'DELETE'});await wp2Connection();nodeCache=[];nodePage=0;renderNodes();nodeCache=[];selectedInstallNodeIDs.clear();filterInstallNodes();document.getElementById('nodehint').textContent='已断开，下次同步将使用 muKey 接口'}catch(e){document.getElementById('wp2connection').textContent=e.message}}

let installationAccount='',installationTargets=[];
function accountLabel(id){const option=Array.from(document.getElementById('account').options).find(x=>x.value===id);return option?option.textContent:id}
function updateInstallTargets(instances,account,previous){
 installationTargets=instances;
 const select=document.getElementById('instance');select.replaceChildren();
 const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent=account?'请选择运行中的 Linode 服务器':'请先在上方选择具体 Linode 账号';select.appendChild(placeholder);
 document.getElementById('installaccount').textContent=account?'当前 Linode 账号：'+accountLabel(account):'当前为全部账号视图，请先在上方选择具体 Linode 账号';
 if(!account){select.disabled=true;updateDNSTarget();return}select.disabled=false;
 const available=instances.filter(i=>i.account_id===account&&i.status==='running');
 for(const instance of available){const option=document.createElement('option');option.value=String(instance.id);option.textContent=instance.label+' (#'+instance.id+') — '+(instance.ipv4||[]).join(', ')+' / '+(instance.region||'');select.appendChild(option)}
 select.value=available.some(i=>String(i.id)===previous)?previous:(available.length===1?String(available[0].id):'');
 installationAccount=account;
 if(!available.length)document.getElementById('installaccount').textContent+='；没有运行中的服务器，请先创建或开机';updateDNSTarget();
}

let poolAccounts=[],poolEntries=[],poolBusy=false;
function fillProxyChoices(id,proxies,emptyLabel){const select=document.getElementById(id),previous=select.value;select.replaceChildren();const none=document.createElement('option');none.value='';none.textContent=emptyLabel;select.appendChild(none);for(const proxy of proxies){const option=document.createElement('option');option.value=proxy.id;const owners=proxy.bound_accounts||[];option.textContent=proxy.name+' · '+proxy.address+(owners.length?' · 已占用':' · 未绑定');option.disabled=id!=='pooledit'&&owners.some(owner=>id==='accountproxy'||owner!==document.getElementById('poolaccount').value);select.appendChild(option)}select.value=Array.from(select.options).some(o=>o.value===previous&&!o.disabled)?previous:''}
async function loadProxyPool(){const data=await api('/proxy-pool'),proxies=data.proxies||[];poolEntries=proxies;fillProxyChoices('accountproxy',proxies,'直连（不绑定代理）');fillProxyChoices('poolproxy',proxies,'直连（解除代理绑定）');fillProxyChoices('pooledit',proxies,'请选择要修改的代理');selectPoolEdit()}
function selectPoolEdit(){const entry=poolEntries.find(p=>p.id===document.getElementById('pooledit').value);document.getElementById('pooleditname').value=entry?.name||'';document.getElementById('poolediturl').value='';document.getElementById('poolediturl').placeholder=entry?'当前：'+entry.address+'；留空保留完整配置':'填写完整新代理 URL';document.getElementById('pooleditmsg').textContent=''}
async function savePoolEdit(){if(poolBusy)return;const id=document.getElementById('pooledit').value,name=document.getElementById('pooleditname').value.trim(),input=document.getElementById('poolediturl'),url=input.value.trim(),message=document.getElementById('pooleditmsg');if(!id||!name){message.textContent='请选择代理并填写名称';return}setPoolBusy(true);let saved=false;try{await api('/proxy-pool/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify({name,url})});saved=true;input.value='';document.getElementById('poolbilling').replaceChildren();await loadProxyPool();await proxyStatus();message.textContent='代理资料已更新，绑定账号会使用新配置，可重新测试余额。'}catch(e){message.textContent=(saved?'修改已保存，刷新失败：':'')+e.message}finally{setPoolBusy(false)}}
async function openProxyPool(){document.getElementById('proxypooldialog').showModal();document.getElementById('poolmsg').textContent='';document.getElementById('poolbilling').replaceChildren();try{const data=await api('/accounts');poolAccounts=data.accounts||[];const select=document.getElementById('poolaccount'),previous=select.value;select.replaceChildren();const none=document.createElement('option');none.value='';none.textContent='请选择账号';select.appendChild(none);for(const account of poolAccounts){const option=document.createElement('option');option.value=account.id;option.textContent=account.name;select.appendChild(option)}select.value=poolAccounts.some(a=>a.id===previous)?previous:(poolAccounts.some(a=>a.id===document.getElementById('account').value)?document.getElementById('account').value:'');await loadProxyPool();await poolAccountChanged()}catch(e){document.getElementById('poolmsg').textContent=e.message}}
async function poolAccountChanged(){const account=document.getElementById('poolaccount').value;document.getElementById('poolbilling').replaceChildren();document.getElementById('poolmsg').textContent='';fillProxyChoices('poolproxy',poolEntries,'直连（解除代理绑定）');document.getElementById('poolproxy').value='';if(!account)return;try{const config=await api('/linode/proxy?account_id='+encodeURIComponent(account));if(document.getElementById('poolaccount').value!==account)return;document.getElementById('poolproxy').value=config.pool_id||'';document.getElementById('poolmsg').textContent=config.configured?(config.pool_id?'已绑定池内代理：':'已绑定旧版手动代理：')+config.address+(config.enabled?'':'（操作代理已停用，余额测试仍使用此代理）'):'该账号当前使用直连'}catch(e){if(document.getElementById('poolaccount').value===account)document.getElementById('poolmsg').textContent=e.message}}
function poolProxyChanged(){document.getElementById('poolbilling').replaceChildren();document.getElementById('poolmsg').textContent='选择已更改，请点击绑定代理保存。'}
function setPoolBusy(busy){poolBusy=busy;for(const id of ['poolaccount','poolproxy','poolbind','pooltestbalance','poolimport','pooledit','pooleditname','poolediturl','pooleditsave'])document.getElementById(id).disabled=busy}
async function bindPoolProxy(){if(poolBusy)return;const account=document.getElementById('poolaccount').value,id=document.getElementById('poolproxy').value,message=document.getElementById('poolmsg');if(!account){message.textContent='请选择要绑定的账号';return}setPoolBusy(true);document.getElementById('poolbilling').replaceChildren();try{await api('/proxy-pool?account_id='+encodeURIComponent(account),{method:'PUT',body:JSON.stringify({id})});await loadProxyPool();if(document.getElementById('account').value===account)await proxyStatus();message.textContent=(poolAccounts.find(a=>a.id===account)?.name||account)+(id?'：代理已绑定并启用，可测试余额。':'：已解除代理绑定，使用直连。')}catch(e){message.textContent=e.message}finally{setPoolBusy(false)}}
async function testPoolBalance(){if(poolBusy)return;const account=document.getElementById('poolaccount').value,id=document.getElementById('poolproxy').value,message=document.getElementById('poolmsg'),box=document.getElementById('poolbilling');box.replaceChildren();if(!account){message.textContent='请选择要测试的账号';return}setPoolBusy(true);try{const config=await api('/linode/proxy?account_id='+encodeURIComponent(account));if(Boolean(config.configured)!==Boolean(id)||(id&&(config.pool_id!==id)))throw Error('请先绑定所选代理，再测试余额');message.textContent='正在测试所选账号余额…';const data=await api('/accounts/'+encodeURIComponent(account)+'/billing?account_id='+encodeURIComponent(account)+'&use_proxy='+(id?'true':'false'));renderBilling(data,box);message.textContent=(poolAccounts.find(a=>a.id===account)?.name||account)+'：余额测试通过（'+(id?'已绑定代理':'直连')+'）。'}catch(e){message.textContent='余额测试未通过：'+e.message}finally{setPoolBusy(false)}}
async function importProxies(){const button=document.getElementById('poolimport');if(button.disabled)return;button.disabled=true;try{await api('/proxy-pool',{method:'POST',body:JSON.stringify({lines:document.getElementById('proxybatch').value})});document.getElementById('proxybatch').value='';await loadProxyPool();document.getElementById('poolmsg').textContent='代理已加入池，可选择账号进行绑定。'}catch(e){document.getElementById('poolmsg').textContent=e.message}finally{button.disabled=false}}
async function changeAccount(){await proxyStatus();await Promise.all([load(),monitor(),queryAccountBilling()])}
async function toggleProxy(){try{await api('/linode/proxy',{method:'PUT',body:JSON.stringify({enabled:document.getElementById('useproxy').checked})});await proxyStatus();await load()}catch(e){await proxyStatus();document.getElementById('proxystatus').textContent=e.message}}
async function proxyStatus(){const account=document.getElementById('account').value;try{if(!account){document.getElementById('useproxy').checked=false;document.getElementById('proxystatus').textContent='请先选择账号配置代理';return}const result=await api('/linode/proxy');if(account!==document.getElementById('account').value)return;document.getElementById('useproxy').checked=result.configured&&(result.enabled!==false);document.getElementById('proxystatus').textContent=result.configured?'已绑定代理：'+result.address+' · '+(document.getElementById('useproxy').checked?'已启用，可测试余额':'操作代理已停用；余额仍走绑定代理'):'当前账号使用直连，可在代理池绑定代理'}catch(e){document.getElementById('proxystatus').textContent=e.message}}

let watchedJob='';
async function watchJob(id){watchedJob=id;const button=document.getElementById('installbutton'),replace=document.getElementById('replacebutton');button.disabled=true;replace.disabled=true;try{while(watchedJob===id){const result=await api('/deployments/'+encodeURIComponent(id));showJob(result);if(['success','failed','partial','interrupted'].includes(result.status)){if(result.status==='success'&&!result.kind)button.textContent='重新安装（会重启后端）';break;}await new Promise(resolve=>setTimeout(resolve,2500))}}catch(e){show('joblog',e.message)}finally{if(watchedJob===id){watchedJob='';button.disabled=false;replace.disabled=false}}}

let nodeCache=[],nodePage=0,selectedInstallNodeIDs=new Set();
function rememberInstallNodes(){const select=document.getElementById('node'),visible=new Set(Array.from(select.options).map(option=>option.value));for(const id of visible)selectedInstallNodeIDs.delete(id);for(const option of select.selectedOptions)if(option.value)selectedInstallNodeIDs.add(option.value);document.getElementById('selectednodes').textContent=selectedInstallNodeIDs.size?'已选择 '+selectedInstallNodeIDs.size+' 个节点；可按住 Ctrl / ⌘ 多选':'增加节点会保留已安装节点及 Hysteria2 端口跳跃规则。'}
function filterInstallNodes(){const select=document.getElementById('node');const query=document.getElementById('nodefilter').value.trim().toLowerCase();select.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent=query?'搜索结果（可多选）':'请选择一个或多个节点';empty.disabled=true;select.appendChild(empty);for(const n of nodeCache.filter(n=>[n.id,n.name,n.sort].some(v=>String(v||'').toLowerCase().includes(query)))){const option=document.createElement('option');option.value=String(n.id);option.textContent=String(n.name||'节点')+' (#'+n.id+') · '+String(n.sort||'未知协议');option.selected=selectedInstallNodeIDs.has(option.value);select.appendChild(option)}rememberInstallNodes()}
function renderNodes(){
 const query=document.getElementById('nodesearch').value.trim().toLowerCase();
 const matches=nodeCache.filter(node=>String(node.id).includes(query)||String(node.name||'').toLowerCase().includes(query));
 const pages=Math.max(1,Math.ceil(matches.length/10));nodePage=Math.max(0,Math.min(nodePage,pages-1));
 document.getElementById('nodes').innerHTML='<table><tr><th>ID</th><th>节点名称</th><th>类型</th></tr>'+matches.slice(nodePage*10,nodePage*10+10).map(node=>'<tr><td>'+esc(node.id)+'</td><td>'+esc(node.name)+'</td><td>'+esc(node.sort)+'</td></tr>').join('')+'</table>';
 document.getElementById('nodespage').textContent='第 '+(nodePage+1)+' / '+pages+' 页，共 '+matches.length+' 个节点';document.getElementById('nodesprev').disabled=nodePage===0;document.getElementById('nodesnext').disabled=nodePage>=pages-1;
}

function dnsFields(){const ali=document.getElementById('dnsprovider').value==='alidns';document.getElementById('cfkeyfields').hidden=ali;document.getElementById('alikeyfields').hidden=!ali}
async function loadDNS(){try{const result=await api('/dns/providers');const root=document.getElementById('dnsconfigs');root.replaceChildren();for(const config of result.providers){const row=document.createElement('p');row.textContent=config.zone+' · '+(config.provider==='alidns'?'阿里云':'Cloudflare')+' · '+(config.enabled?'自动更新已启用':'自动更新已关闭');const check=document.createElement('button');check.textContent='验证读取权限';check.onclick=async()=>{try{const status=await api('/dns/check?zone='+encodeURIComponent(config.zone));document.getElementById('dnsmsg').textContent=status.message}catch(e){document.getElementById('dnsmsg').textContent=e.message}};const remove=document.createElement('button');remove.textContent='删除配置';remove.onclick=async()=>{if(!confirm('删除 '+config.zone+' 的 DNS 配置？不会删除云端 DNS 记录。'))return;try{await api('/dns/providers?zone='+encodeURIComponent(config.zone),{method:'DELETE'});await loadDNS()}catch(e){document.getElementById('dnsmsg').textContent=e.message}};const toggle=document.createElement('button');toggle.textContent=config.enabled?'暂停自动更新':'启用自动更新';toggle.onclick=async()=>{try{await api('/dns/providers?zone='+encodeURIComponent(config.zone),{method:'PATCH',body:JSON.stringify({enabled:!config.enabled})});await loadDNS()}catch(e){document.getElementById('dnsmsg').textContent=e.message}};row.appendChild(check);row.appendChild(toggle);row.appendChild(remove);root.appendChild(row)}}catch(e){document.getElementById('dnsmsg').textContent=e.message}}
async function saveDNS(){const message=document.getElementById('dnsmsg');try{await api('/dns/providers',{method:'POST',body:JSON.stringify({zone:document.getElementById('dnszone').value,provider:document.getElementById('dnsprovider').value,token:document.getElementById('dnstoken').value,access_key_id:document.getElementById('dnsaccessid').value,access_key_secret:document.getElementById('dnssecret').value,enabled:document.getElementById('dnsenabled').checked})});for(const id of ['dnstoken','dnsaccessid','dnssecret'])document.getElementById(id).value='';message.textContent='DNS Key 已加密保存；可验证读取权限，安装时验证记录写入权限。';await loadDNS()}catch(e){message.textContent=e.message}}

async function loadTelegram(){try{const config=await api('/telegram/settings');document.getElementById('tgchat').value=config.chat_id||'';document.getElementById('tgenabled').checked=config.configured?config.enabled:true;document.getElementById('tgstatus').textContent=config.configured?(config.enabled?'Telegram 已配置并启用':'Telegram 已配置，提醒已暂停'):'尚未配置 Telegram 机器人'}catch(e){document.getElementById('tgmsg').textContent=e.message}}
async function saveTelegram(){try{await api('/telegram/settings',{method:'POST',body:JSON.stringify({token:document.getElementById('tgtoken').value,chat_id:document.getElementById('tgchat').value,enabled:document.getElementById('tgenabled').checked})});document.getElementById('tgtoken').value='';document.getElementById('tgmsg').textContent='Telegram 配置已加密保存。';await loadTelegram()}catch(e){document.getElementById('tgmsg').textContent=e.message}}
async function testTelegram(){const button=document.getElementById('tgtest');if(button.disabled)return;button.disabled=true;try{const result=await api('/telegram/test',{method:'POST',body:'{}'});document.getElementById('tgmsg').textContent=result.message}catch(e){document.getElementById('tgmsg').textContent=e.message}finally{button.disabled=false}}
async function removeTelegram(){if(!confirm('移除网页保存的 Telegram 配置？如 .env 中仍有配置，将恢复使用 .env 配置。'))return;try{await api('/telegram/settings',{method:'DELETE'});document.getElementById('tgtoken').value='';await loadTelegram()}catch(e){document.getElementById('tgmsg').textContent=e.message}}

function updateDNSTarget(){const instance=installationTargets.find(x=>String(x.id)===document.getElementById('instance').value&&x.account_id===document.getElementById('account').value);document.getElementById('dnstarget').textContent=instance?'DNS 解析目标：'+instance.label+' (#'+instance.id+') · A → '+(instance.ipv4||[]).join(', ')+(instance.ipv6?' · AAAA → '+instance.ipv6.split('/')[0]:' · 无 IPv6 时清理旧 AAAA'):'请选择安装目标服务器，DNS 将指向该实例公网 IP，而不是管理机 IP。'}
async function discoverDNS(){const button=document.getElementById('dnsdiscover'),message=document.getElementById('dnsmsg');if(button.disabled)return;button.disabled=true;message.textContent='正在读取托管域名并匹配当前 wp2 节点…';try{const result=await api('/dns/discover',{method:'POST',body:JSON.stringify({provider:document.getElementById('dnsprovider').value,token:document.getElementById('dnstoken').value,access_key_id:document.getElementById('dnsaccessid').value,access_key_secret:document.getElementById('dnssecret').value,node_id:Number(document.getElementById('node').value)||0})});const select=document.getElementById('dnszones');select.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='选择托管域名';select.appendChild(empty);for(const zone of result.zones){const option=document.createElement('option');option.value=zone;option.textContent=zone;select.appendChild(option)}select.value=result.suggested_zone||'';document.getElementById('dnszone').value=result.suggested_zone||'';message.textContent=result.message||'读取到 '+result.zones.length+' 个托管域名。'+(result.suggested_zone?'已自动选择 '+result.suggested_zone+'，保存后安装时解析到所选实例 IP。':'请选择正确域名后保存。')}catch(e){message.textContent=e.message}finally{button.disabled=false}}

async function backendLogs(){const account=document.getElementById('account').value,id=Number(document.getElementById('instance').value),button=document.getElementById('backendlogbutton');if(!account||!Number.isInteger(id)||id<=0){show('joblog','请先选择具体账号和服务器');return}if(button.disabled)return;button.disabled=true;try{const result=await api('/instances/'+id+'/backend/logs');document.getElementById('joblog').textContent='后端服务状态：'+result.service+'\n'+result.log}catch(e){show('joblog',e.message)}finally{button.disabled=false}}

let ipChangeTarget=null,lastIPJob=null;
function showJob(result){show('joblog',result);if(result.kind==='ip_change'){lastIPJob=result;document.getElementById('ipcleanup').hidden=!result.helper_id||result.helper_cleaned||!['failed','interrupted'].includes(result.status)}else{document.getElementById('ipcleanup').hidden=true}}
async function openIPChange(instance){try{const result=await api('/instances/'+instance.id+'/ip-change-plan?account_id='+encodeURIComponent(instance.account_id));ipChangeTarget=result.instance;const nodes=document.getElementById('ipnode');nodes.replaceChildren();const none=document.createElement('option');none.value='';none.textContent='自动使用已保存的域名绑定（首次使用请选择节点）';nodes.appendChild(none);for(const node of nodeCache){const option=document.createElement('option');option.value=String(node.id);option.textContent=node.name+' (#'+node.id+')';nodes.appendChild(option)}nodes.value=result.bound_node_id?String(result.bound_node_id):(String(instance.id)===document.getElementById('instance').value?document.getElementById('node').value:'');document.getElementById('ipsummary').textContent='原机：'+instance.label+' (#'+instance.id+')\n当前 IP：'+(instance.ipv4||[]).join(', ')+'\n地区：'+instance.region+'\n'+(result.billing_notice||'');document.getElementById('ipcheckport').value='22';document.getElementById('ipcheckchinaoriginal').checked=true;document.getElementById('ipbilling').checked=false;document.getElementById('iperror').textContent='';await loadChinaProbeSettings();document.getElementById('ipchangedialog').showModal()}catch(e){document.getElementById('msg').textContent=e.message}}
function openChinaTCPCheck(){if(!ipChangeTarget){document.getElementById('iperror').textContent='请先选择服务器';return}const port=Number(document.getElementById('ipcheckport').value),ip=(ipChangeTarget.ipv4||[])[0];if(!ip||!Number.isInteger(port)||port<1||port>65535){document.getElementById('iperror').textContent='请检查服务器 IP 和 1-65535 的 TCP 端口';return}window.open('https://tcp.ping.pe/'+ip+':'+port,'_blank','noopener,noreferrer')}
async function startIPChange(){const button=document.getElementById('ipconfirm'),message=document.getElementById('iperror');if(button.disabled)return;const checkPort=Number(document.getElementById('ipcheckport').value);if(!Number.isInteger(checkPort)||checkPort<1||checkPort>65535){message.textContent='TCP 检查端口必须是 1-65535 的整数';return}if(!ipChangeTarget||!document.getElementById('ipbilling').checked){message.textContent='请确认额外 IPv4 可能产生的费用及短暂停机';return}if(prompt('保留原机；先申请新 IPv4 并验证，再释放旧地址。请输入原机 ID '+ipChangeTarget.id+' 确认：')!==String(ipChangeTarget.id))return;button.disabled=true;try{const result=await api('/instances/'+ipChangeTarget.id+'/change-ip?account_id='+encodeURIComponent(ipChangeTarget.account_id),{method:'POST',body:JSON.stringify({expected_ip:ipChangeTarget.ipv4[0],confirm_instance_id:ipChangeTarget.id,confirm_billing:true,node_id:Number(document.getElementById('ipnode').value)||0,check_port:checkPort,china_probe:true,check_china_original:document.getElementById('ipcheckchinaoriginal').checked})});document.getElementById('ipchangedialog').close();document.getElementById('job').value=result.job_id;watchJob(result.job_id);document.getElementById('deploy').scrollIntoView?.({behavior:'smooth'})}catch(e){message.textContent=e.message}finally{button.disabled=false}}
async function cleanupIPChange(){if(!lastIPJob||!confirm('仅清理换 IP 任务创建的空临时实例，原机 #'+lastIPJob.instance_id+' 不会删除。确认继续？'))return;try{await api('/ip-changes/'+encodeURIComponent(lastIPJob.job_id)+'/cleanup',{method:'POST',body:JSON.stringify({confirm_instance_id:lastIPJob.instance_id})});showJob(await api('/deployments/'+encodeURIComponent(lastIPJob.job_id)));await loadIPChanges()}catch(e){show('joblog',e.message)}}
async function loadIPChanges(){try{const result=await api('/ip-changes');const root=document.getElementById('ipchanges');root.replaceChildren();for(const item of result.jobs){const button=document.createElement('button');button.textContent='#'+item.instance_id+' · '+item.status+' · '+(item.new_ip||'待更换');button.onclick=()=>{document.getElementById('job').value=item.job_id;watchJob(item.job_id)};root.appendChild(button)}}catch(e){document.getElementById('ipchanges').textContent=e.message}}
async function loadChinaProbeSettings(){try{const [aliyun,iptrace,boot]=await Promise.all([api('/domestic-probe/settings'),api('/iptrace-probe/settings'),api('/china-probe/boot-settings')]);document.getElementById('cnprobehost').value=aliyun.host||'';document.getElementById('cnprobeport').value=aliyun.port||22;document.getElementById('cnprobeuser').value=aliyun.user||'root';document.getElementById('bootipcheck').checked=boot.settings.enabled;document.getElementById('bootipreplace').checked=boot.settings.auto_replace;document.getElementById('bootipport').value=boot.settings.port||22;const provider=aliyun.selected_provider||iptrace.selected_provider||'aliyun';const label=provider==='iptrace'?'IPTrace 中国节点 API':'阿里云 SSH 探测机';const ready=provider==='iptrace'?iptrace.configured:aliyun.configured;document.getElementById('chinaprobestatus').textContent='当前探测方式：'+label+' · '+(ready?'已配置':'尚未配置')+' · 开机检测 '+(boot.settings.enabled?'已启用':'已关闭');document.getElementById('cnprobehint').textContent=ready?'换 IP 时使用 '+label+' 检查 TCP/'+document.getElementById('ipcheckport').value+'；开机时检查 TCP/'+(boot.settings.port||22)+'。': '请先在“国内探测”设置中配置并启用一种探测方式。'}catch(e){document.getElementById('chinaprobestatus').textContent='读取国内探测配置失败：'+e.message;document.getElementById('cnprobehint').textContent='国内探测配置不可用，换 IP 前请先修复。'}}
async function saveChinaBootSettings(){const message=document.getElementById('chinaprobemsg');try{await api('/china-probe/boot-settings',{method:'POST',body:JSON.stringify({enabled:document.getElementById('bootipcheck').checked,port:Number(document.getElementById('bootipport').value),auto_replace:document.getElementById('bootipreplace').checked})});message.textContent='开机 IP 检测设置已保存。';await loadChinaProbeSettings()}catch(e){message.textContent=e.message}}
async function saveDomesticProbe(){const message=document.getElementById('chinaprobemsg');try{await api('/domestic-probe/settings',{method:'POST',body:JSON.stringify({host:document.getElementById('cnprobehost').value,port:Number(document.getElementById('cnprobeport').value),user:document.getElementById('cnprobeuser').value,password:document.getElementById('cnprobepassword').value})});document.getElementById('cnprobepassword').value='';message.textContent='SSH 连接验证成功，已加密保存并启用阿里云探测。';await loadChinaProbeSettings()}catch(e){message.textContent=e.message}}
async function removeDomesticProbe(){if(!confirm('删除加密保存的阿里云探测机 SSH 配置？'))return;try{await api('/domestic-probe/settings',{method:'DELETE'});await loadChinaProbeSettings();document.getElementById('chinaprobemsg').textContent='阿里云探测机配置已删除。'}catch(e){document.getElementById('chinaprobemsg').textContent=e.message}}
async function saveIPTraceProbe(){const input=document.getElementById('iptracekey'),message=document.getElementById('chinaprobemsg');try{await api('/iptrace-probe/settings',{method:'POST',body:JSON.stringify({key:input.value})});input.value='';message.textContent='IPTrace Key 验证成功，已加密保存并启用。检测请求每次中国节点 TCP 探测会消耗 4 点。';await loadChinaProbeSettings()}catch(e){message.textContent=e.message}}
async function removeIPTraceProbe(){if(!confirm('删除加密保存的 IPTrace API Key？'))return;try{await api('/iptrace-probe/settings',{method:'DELETE'});await loadChinaProbeSettings();document.getElementById('chinaprobemsg').textContent='IPTrace Key 已删除。'}catch(e){document.getElementById('chinaprobemsg').textContent=e.message}}
async function selectChinaProbe(provider){try{await api('/china-probe/provider',{method:'PUT',body:JSON.stringify({provider})});await loadChinaProbeSettings();document.getElementById('chinaprobemsg').textContent='已切换到'+(provider==='aliyun'?'阿里云 SSH 探测机':'IPTrace 中国节点 API')+'。'}catch(e){document.getElementById('chinaprobemsg').textContent=e.message}}
async function initialize(){await loadAccounts();try{await loadProxyPool()}catch(e){}await proxyStatus();await Promise.all([load(),nodes(),monitor(),wp2Connection(),loadDNS(),loadTelegram(),loadChinaProbeSettings()])}initialize();setInterval(()=>monitor(),30000)</script></html>`
