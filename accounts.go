package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ManagedAccount struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"-"`
}
type storedAccount struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}
type accountStore struct {
	mu       sync.RWMutex
	key      [32]byte
	file     string
	accounts map[string]storedAccount
}

func initAccounts(file, key string) (*accountStore, error) {
	if len(key) < 32 {
		return nil, errors.New("ACCOUNT_ENCRYPTION_KEY must be at least 32 characters")
	}
	s := &accountStore{key: sha256.Sum256([]byte(key)), file: file, accounts: map[string]storedAccount{}}
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read account store: %w", err)
	}
	if len(b) < 13 {
		return nil, errors.New("encrypted account store is invalid")
	}
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(b) <= n {
		return nil, errors.New("encrypted account store is invalid")
	}
	plain, err := gcm.Open(nil, b[:n], b[n:], nil)
	if err != nil {
		return nil, errors.New("account store decryption failed; verify ACCOUNT_ENCRYPTION_KEY")
	}
	var data []storedAccount
	if err = json.Unmarshal(plain, &data); err != nil {
		return nil, errors.New("account store has invalid data")
	}
	for _, a := range data {
		if a.ID == "" || a.Token == "" || a.Name == "" {
			return nil, errors.New("account store contains incomplete record")
		}
		s.accounts[a.ID] = a
	}
	return s, nil
}
func (s *accountStore) saveLocked() error {
	entries := make([]storedAccount, 0, len(s.accounts))
	for _, a := range s.accounts {
		entries = append(entries, a)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	plain, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	encrypted := gcm.Seal(nonce, nonce, plain, nil)
	if err = os.MkdirAll(filepath.Dir(s.file), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.file), ".accounts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(encrypted); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.file)
}
func (s *accountStore) list() []ManagedAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ManagedAccount, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, ManagedAccount{ID: a.ID, Name: a.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (s *accountStore) token(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.accounts[id]
	return a.Token, ok
}
func (s *accountStore) add(name, token string) (ManagedAccount, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 80 || len(token) < 20 || len(token) > 512 {
		return ManagedAccount{}, errors.New("account name (1-80) or API token (20-512) is invalid")
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return ManagedAccount{}, err
	}
	a := storedAccount{ID: hex.EncodeToString(idb), Name: name, Token: token}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.accounts {
		if v.Name == a.Name {
			return ManagedAccount{}, errors.New("account name already exists")
		}
	}
	s.accounts[a.ID] = a
	if err := s.saveLocked(); err != nil {
		delete(s.accounts, a.ID)
		return ManagedAccount{}, err
	}
	return ManagedAccount{ID: a.ID, Name: a.Name}, nil
}
func (s *accountStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.accounts[id]
	if !ok {
		return os.ErrNotExist
	}
	delete(s.accounts, id)
	if err := s.saveLocked(); err != nil {
		s.accounts[id] = old
		return err
	}
	return nil
}
func (s *Server) accountToken(id string) (string, error) {
	if id == "" || id == "legacy" {
		if !s.legacyEnabled() {
			return "", errors.New("默认账号已移除或未配置")
		}
		t := os.Getenv("LINODE_TOKEN")
		if t == "" {
			return "", errors.New("legacy LINODE_TOKEN not configured")
		}
		return t, nil
	}
	if s.accounts == nil {
		return "", errors.New("account store not configured")
	}
	t, ok := s.accounts.token(id)
	if !ok {
		return "", errors.New("unknown account")
	}
	return t, nil
}
func (s *Server) linodeFor(ctx context.Context, accountID, method, path string, payload io.Reader) ([]byte, int, error) {

	strict, _ := ctx.Value(isolationContextKey{}).(bool)
	if strict || s.isolationEnabled() {
		if _, err := s.verifyAccountEgress(ctx, accountID); err != nil {
			return nil, 503, err
		}
		ctx = useProxyContext(ctx, true)
	}
	token, err := s.accountToken(accountID)
	if err != nil {
		return nil, 503, err
	}
	if s.linodeHook != nil {
		return s.linodeHook(ctx, accountID, method, path, payload)
	}
	base := env("LINODE_API_BASE_URL", "https://api.linode.com/v4")
	if enabled, _ := ctx.Value(proxyContextKey{}).(bool); enabled {
		proxy, err := s.proxyForRequest(accountID)
		if err != nil {
			return nil, 503, err
		}
		client, err := proxyClient(s.client, proxy)
		if err != nil {
			return nil, 503, err
		}
		defer client.CloseIdleConnections()
		temporary := &Server{client: client}
		b, status, err := temporary.request(ctx, method, strings.TrimRight(base, "/")+path, token, payload)
		if err != nil {
			return nil, 502, fmt.Errorf("Linode 代理请求失败：%s；未切换直连", safeProxyFailure(err))
		}
		return b, status, nil
	}
	return s.request(ctx, method, strings.TrimRight(base, "/")+path, token, payload)
}
func (s *Server) accountsAPI(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		fail(w, 503, "Configure ACCOUNT_ENCRYPTION_KEY (32+ chars) to use multiple accounts")
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := s.accounts.list()
		if s.legacyEnabled() {
			out = append([]ManagedAccount{{ID: "legacy", Name: "默认账号 (.env)"}}, out...)
		}
		send(w, 200, map[string]any{"accounts": out})
	case http.MethodPost:
		var in struct {
			Name     string `json:"name"`
			Token    string `json:"token"`
			ProxyURL string `json:"proxy_url"`
			ProxyID  string `json:"proxy_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
			fail(w, 400, "Invalid account payload")
			return
		}
		if strings.TrimSpace(in.ProxyURL) != "" {
			parsed, err := validateProxyURL(in.ProxyURL)
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			if s.credentials == nil {
				fail(w, 503, "代理加密存储未配置，账号未创建")
				return
			}
			in.ProxyURL = parsed.String()
		}
		if in.ProxyID != "" {
			if _, ok := s.poolURL(in.ProxyID); !ok {
				fail(w, 400, "所选代理不存在，账号未创建")
				return
			}
			in.ProxyURL = "pool:" + in.ProxyID
		}
		a, err := s.accounts.add(in.Name, in.Token)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if in.ProxyURL != "" {
			if err := s.saveProxyConfig(a.ID, in.ProxyURL); err != nil {
				if rollbackErr := s.accounts.remove(a.ID); rollbackErr != nil {
					fail(w, 500, "账号已创建但代理保存失败，请刷新账号列表，勿重复添加")
					return
				}
				if errors.Is(err, errProxyAlreadyBound) {
					fail(w, 409, err.Error()+"；账号未创建")
					return
				}
				fail(w, 500, "代理保存失败，账号创建已撤销")
				return
			}
		}
		send(w, 201, a)
	default:
		fail(w, 405, "Method not allowed")
	}
}

// accountBilling returns only the fields used by the dashboard. The upstream
// /account response includes billing address and contact details, which must
// never be forwarded to the browser.
func (s *Server) accountBilling(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		fail(w, 400, "请先选择 Linode 账号")
		return
	}
	// Balance queries always follow the saved binding, independently of the
	// operation toggle or caller-supplied use_proxy parameter. A broken binding
	// must fail rather than silently send the account token directly.
	bound := false
	if s.credentials != nil {
		_, bound = s.credentials.token("linode-proxy-" + id + "/0")
	}
	ctx := useProxyContext(r.Context(), bound)
	body, status, err := s.linodeFor(ctx, id, http.MethodGet, "/account", nil)
	if err != nil {
		message := "Linode 直连查询失败：" + safeProxyFailure(err)
		if bound {
			message = err.Error()
		}
		fail(w, 502, message)
		return
	}
	if status != http.StatusOK {
		if status == http.StatusUnauthorized {
			fail(w, status, "Linode Token 无效或已过期，请更新当前账号的 Token")
			return
		}
		if status == http.StatusForbidden {
			fail(w, status, "Token 缺少账号只读权限（Account: Read Only / view_account）")
			return
		}
		fail(w, status, fmt.Sprintf("Linode 账号查询失败（HTTP %d）", status))
		return
	}
	var account struct {
		Balance           float64 `json:"balance"`
		BalanceUninvoiced float64 `json:"balance_uninvoiced"`
		ActivePromotions  []struct {
			Summary                string `json:"summary"`
			CreditRemaining        string `json:"credit_remaining"`
			MonthlyCreditRemaining string `json:"this_month_credit_remaining"`
			CreditMonthlyCap       string `json:"credit_monthly_cap"`
			ExpireAt               string `json:"expire_dt"`
			ServiceType            string `json:"service_type"`
		} `json:"active_promotions"`
	}
	if err := json.Unmarshal(body, &account); err != nil {
		fail(w, 502, "Linode 账号账单数据格式无效")
		return
	}
	send(w, 200, map[string]any{
		"balance": account.Balance, "balance_uninvoiced": account.BalanceUninvoiced,
		"active_promotions": account.ActivePromotions,
	})
}
func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if !s.refillMu.TryRLock() {
		fail(w, 409, "补号或账户运维正在运行，请等待")
		return
	}
	defer s.refillMu.RUnlock()
	if s.accounts == nil {
		fail(w, 503, "Account storage unavailable")
		return
	}
	id := r.PathValue("id")
	s.mu.RLock()
	busy := false
	for _, job := range s.jobs {
		if job.Kind == "ip_change" && job.AccountID == id && (job.Status == "queued" || job.Status == "running") {
			busy = true
		}
	}
	s.mu.RUnlock()
	if busy {
		fail(w, 409, "账号正在换 IP，请等待临时实例清理完成")
		return
	}
	if id == "legacy" {
		if !s.legacyEnabled() {
			fail(w, 404, "Account not found")
			return
		}
		if err := s.saveRootPassword("disabled-account", 0, "Default Linode account", "disabled"); err != nil {
			fail(w, 500, "无法保存默认账号移除状态")
			return
		}
		if err := s.clearProxyConfig(id); err != nil {
			fail(w, 500, "默认账号已移除，但代理解绑失败，请核对凭据存储")
			return
		}
		send(w, 200, map[string]bool{"deleted": true})
		return
	}
	err := s.accounts.remove(id)
	if errors.Is(err, os.ErrNotExist) {
		fail(w, 404, "Account not found")
		return
	}
	if err != nil {
		fail(w, 500, "Failed to save account changes")
		return
	}
	if err := s.clearProxyConfig(id); err != nil {
		fail(w, 500, "账号已移除，但代理解绑失败，请核对凭据存储")
		return
	}
	// Do not modify or shut down any Linode instance when an account is removed.
	s.mu.Lock()
	for k := range s.accountStatus {
		if strings.HasPrefix(k, id+"/") {
			delete(s.accountStatus, k)
		}
	}
	s.mu.Unlock()
	send(w, 200, map[string]bool{"deleted": true})
}

func (s *Server) pollAccounts(ctx context.Context) {
	if s.accounts == nil {
		return
	}
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, account := range s.accounts.list() {
		instances, err := s.instancesFor(ctx, account.ID)
		if err != nil {
			log.Printf("monitor: account %s lookup failed: %v", account.ID, err)
			continue
		}
		for _, inst := range instances {
			account, inst := account, inst
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				key := account.ID + "/" + strconv.Itoa(inst.ID)
				s.mu.RLock()
				old := s.accountStatus[key]
				s.mu.RUnlock()
				next := Snapshot{AccountID: account.ID, ID: inst.ID, Label: inst.Label, State: "offline", Updated: time.Now().UTC().Format(time.RFC3339)}
				if inst.Status == "running" && publicIP(inst) != "" {
					probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
					output, probeErr := s.deploySSH(probeCtx, account.ID, inst, probeScript)
					cancel()
					if probeErr == nil {
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
						if json.Unmarshal([]byte(output), &metric) == nil && metric.CPU >= 0 && metric.CPU <= 100 && metric.Memory >= 0 && metric.Memory <= 100 && metric.Disk >= 0 && metric.Disk <= 100 && metric.Uptime >= 0 {
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
						} else {
							next.MonitorError = "SSH 探针返回无效监控数据"
						}
					} else {
						next.MonitorError = probeErr.Error()
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
				if s.accountStatus == nil {
					s.accountStatus = map[string]Snapshot{}
				}
				s.accountStatus[key] = next
				s.mu.Unlock()
				if next.Alert != old.Alert {
					if next.Alert != "" {
						go s.telegram(fmt.Sprintf("🚨 Linode [%s] %s (#%d): %s", account.Name, inst.Label, inst.ID, next.Alert))
					}
					if next.Alert == "" && old.Alert != "" {
						go s.telegram(fmt.Sprintf("✅ Linode [%s] %s (#%d) recovered", account.Name, inst.Label, inst.ID))
					}
				}
			}()
		}
	}
	wg.Wait()
}

func (s *Server) legacyEnabled() bool {
	if os.Getenv("LINODE_TOKEN") == "" {
		return false
	}
	if s.credentials != nil {
		if _, disabled := s.credentials.token("disabled-account/0"); disabled {
			return false
		}
	}
	return true
}
