package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type RefillConfig struct {
	Trigger         string   `json:"trigger"`
	ReserveGB       float64  `json:"reserve_gb,omitempty"`
	StopPercent     float64  `json:"stop_percent,omitempty"`
	Enabled         bool     `json:"enabled"`
	Accounts        []string `json:"accounts"`
	Region          string   `json:"region"`
	Type            string   `json:"type"`
	Image           string   `json:"image"`
	Label           string   `json:"label"`
	Script          string   `json:"script"`
	Domain          string   `json:"domain"`
	CreditFloor     float64  `json:"credit_floor"`
	TransferPercent float64  `json:"transfer_percent,omitempty"`
	IntervalMinutes int      `json:"interval_minutes"`
	BootCheck       bool     `json:"boot_check"`
	AutoIP          bool     `json:"auto_ip"`
	CheckPort       int      `json:"check_port"`
	HealthPort      int      `json:"health_port"`
	OldPolicy       string   `json:"old_policy"`
}
type RefillPending struct {
	Account  string `json:"account_id"`
	Label    string `json:"label"`
	ID       int    `json:"instance_id"`
	Password string `json:"password,omitempty"`
}
type RefillEvent struct {
	At      string `json:"at"`
	Message string `json:"message"`
}
type RefillRetired struct {
	Account           string `json:"account_id"`
	ID                int    `json:"instance_id"`
	IP                string `json:"ip"`
	ShutdownRequested bool   `json:"shutdown_requested"`
}
type RefillState struct {
	TaskID         string                    `json:"task_id"`
	Name           string                    `json:"name"`
	CreatedAt      time.Time                 `json:"created_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
	QueuedAction   string                    `json:"queued_action,omitempty"`
	QueuedAt       time.Time                 `json:"queued_at"`
	NextRunAt      time.Time                 `json:"next_run_at"`
	Operation      string                    `json:"operation,omitempty"`
	APIChecks      map[string]RefillAPICheck `json:"api_checks"`
	APIFailures    int                       `json:"api_failures"`
	LastAPIFailure time.Time                 `json:"last_api_failure"`
	CreditAlerted  bool                      `json:"credit_alerted"`
	IPAttempts     int                       `json:"ip_attempts"`
	CurrentCredit  *float64                  `json:"current_credit,omitempty"`
	Retired        []RefillRetired           `json:"retired"`
	Config         RefillConfig              `json:"config"`
	CurrentAccount string                    `json:"current_account"`
	CurrentID      int                       `json:"current_instance"`
	CurrentIP      string                    `json:"current_ip"`
	Cursor         int                       `json:"cursor"`
	Stage          string                    `json:"stage"`
	LastCheck      time.Time                 `json:"last_check"`
	Pending        *RefillPending            `json:"pending,omitempty"`
	History        []RefillEvent             `json:"history"`
}

func defaultRefillConfig() RefillConfig {
	return RefillConfig{Trigger: "api", Label: "refill-node", Image: "linode/debian12", CreditFloor: 0, IntervalMinutes: 1, BootCheck: true, AutoIP: true, CheckPort: 22, HealthPort: 22, OldPolicy: "keep"}
}
func (s *Server) loadRefill() (RefillState, error) { return s.loadRefillTask(defaultRefillTask) }
func (s *Server) saveRefill(st *RefillState, message string) error {
	if s.credentials == nil {
		return errors.New("加密存储未配置")
	}
	if st.TaskID == "" {
		st.TaskID = defaultRefillTask
	}
	if !validRefillTaskID(st.TaskID) {
		return errors.New("任务 ID 无效")
	}
	now := time.Now().UTC()
	if st.CreatedAt.IsZero() {
		st.CreatedAt = now
	}
	st.UpdatedAt = now
	if st.Name == "" {
		st.Name = "默认任务"
	}
	if message != "" {
		st.History = append(st.History, RefillEvent{At: now.Format(time.RFC3339), Message: message})
	}
	if len(st.History) > 200 {
		st.History = st.History[len(st.History)-200:]
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	store := s.credentials
	store.mu.Lock()
	defer store.mu.Unlock()
	if err = checkRefillOwnersLocked(store, *st); err != nil {
		return err
	}

	if st.TaskID != defaultRefillTask {
		if _, exists := store.accounts[refillTaskKey(st.TaskID)]; !exists {
			count := 0
			hasDefault := false
			for key := range store.accounts {
				if id, ok := storedRefillTask(key); ok {
					count++
					hasDefault = hasDefault || id == defaultRefillTask
				}
			}
			if !hasDefault {
				count++
			}
			if count >= 100 {
				return errors.New("最多保存 100 个补机任务")
			}
		}
	}
	key := refillTaskKey(st.TaskID)
	old, exists := store.accounts[key]
	store.accounts[key] = storedAccount{ID: key, Name: st.Name, Token: string(raw)}
	if err = store.saveLocked(); err != nil {
		if exists {
			store.accounts[key] = old
		} else {
			delete(store.accounts, key)
		}
		return err
	}
	return nil
}
func (s *Server) validateRefill(c *RefillConfig) error {
	if len(c.Accounts) == 0 || len(c.Accounts) > 100 {
		return errors.New("请选择 1-100 个账号并排序")
	}
	seen := map[string]bool{}
	for _, id := range c.Accounts {
		if seen[id] {
			return errors.New("账号队列不能重复")
		}
		seen[id] = true
		if _, err := s.accountToken(id); err != nil {
			return errors.New("队列中包含无效账号")
		}
		if _, err := s.proxyForRequest(id); err != nil {
			return errors.New("队列中的每个账号都必须绑定独占代理")
		}
	}
	if !validLinodeLabel(c.Label) || len(c.Label) > 36 {
		return errors.New("名称前缀须为 3-36 位英文名称")
	}
	if c.Region == "" || c.Type == "" || c.Image == "" {
		return errors.New("请选择地区、套餐和镜像")
	}
	if len(c.Script) > 48<<10 {
		return errors.New("脚本不能超过 48KB")
	}
	if math.IsNaN(c.CreditFloor) || math.IsInf(c.CreditFloor, 0) || c.CreditFloor < 0 || c.CreditFloor > 10000 {
		return errors.New("剩余额度阈值无效，只用于提醒，不触发切号")
	}
	if c.IntervalMinutes < 1 || c.IntervalMinutes > 60 || c.CheckPort < 1 || c.CheckPort > 65535 || c.HealthPort < 1 || c.HealthPort > 65535 {
		return errors.New("检查间隔或端口无效")
	}
	c.Trigger = "api"
	c.TransferPercent = 0
	c.ReserveGB = 0
	c.StopPercent = 0
	if c.OldPolicy != "keep" && c.OldPolicy != "shutdown" {
		return errors.New("旧机策略仅支持保留或验证完成后关机")
	}
	if c.BootCheck && !s.chinaProbeConfigured("aliyun") {
		return errors.New("请先配置并验证阿里云国内探测机")
	}
	if c.Domain != "" {
		domain, err := normalizeZone(c.Domain)
		if err != nil {
			return err
		}
		c.Domain = domain
		config, err := s.dnsConfigFor(domain)
		if err != nil || config == nil {
			return errors.New("接替域名需要已启用的 DNS 配置")
		}
		if domain == config.Zone || strings.EqualFold(domain, env("PANEL_DOMAIN", "")) {
			return errors.New("请使用独立的业务子域名，不能使用根域名或面板域名")
		}
	}
	return nil
}
func refillContext(ctx context.Context) context.Context {
	return context.WithValue(useProxyContext(ctx, true), isolationContextKey{}, true)
}

// Refuse absent/null fields; an invalid response must not look like zero credit.
func refillCredit(body []byte, now time.Time) (float64, error) {
	var data struct {
		Balance    *float64 `json:"balance"`
		Pending    *float64 `json:"balance_uninvoiced"`
		Promotions []struct {
			Remaining string `json:"credit_remaining"`
			Month     string `json:"this_month_credit_remaining"`
			Expiry    string `json:"expire_dt"`
			Service   string `json:"service_type"`
		} `json:"active_promotions"`
	}
	if json.Unmarshal(body, &data) != nil || data.Balance == nil || data.Pending == nil || *data.Pending < 0 {
		return 0, errors.New("额度响应不完整，已停止切换")
	}
	credit := -*data.Balance
	for _, p := range data.Promotions {
		if p.Service != "all" && p.Service != "linode" {
			continue
		}
		if p.Expiry != "" {
			expiry, err := time.Parse(time.RFC3339, p.Expiry)
			if err != nil {
				expiry, err = time.Parse("2006-01-02T15:04:05", p.Expiry)
			}
			if err != nil {
				return 0, errors.New("赠金到期时间无效")
			}
			if !expiry.After(now) {
				continue
			}
		}
		total, e1 := strconv.ParseFloat(p.Remaining, 64)
		month, e2 := strconv.ParseFloat(p.Month, 64)
		if e1 != nil || e2 != nil || math.IsNaN(total) || math.IsNaN(month) || math.IsInf(total, 0) || math.IsInf(month, 0) || total < 0 || month < 0 {
			return 0, errors.New("赠金额度数据无效")
		}
		credit += math.Min(total, month)
	}
	// Conservative estimate: reserve all uninvoiced charges before creating.
	return math.Max(credit-*data.Pending, 0), nil
}

func (s *Server) refillAccountCredit(ctx context.Context, account string) (float64, error) {
	body, status, err := s.linodeFor(ctx, account, "GET", "/account", nil)
	if err != nil {
		return 0, err
	}
	if status != 200 {
		return 0, fmt.Errorf("账号额度查询 HTTP %d，未判定为额度耗尽", status)
	}
	return refillCredit(body, time.Now().UTC())
}

func (s *Server) runRefill(ctx context.Context, st *RefillState, resume bool) error {
	ctx = refillContext(ctx)
	s.mu.RLock()
	active := false
	for _, job := range s.jobs {
		if job.Status == "running" || job.Status == "queued" {
			active = true
			break
		}
	}
	s.mu.RUnlock()
	if active {
		return errors.New("已有实例运维任务正在运行，补号已暂停，请等待原任务结束")
	}
	st.LastCheck = time.Now().UTC()
	if st.Pending != nil {
		if !resume {
			return errors.New("存在未完成建机记录，请核对后使用恢复按钮，禁止重复建机")
		}
		if st.Pending.ID == 0 {
			instances, err := s.instancesFor(ctx, st.Pending.Account)
			if err != nil {
				return err
			}
			count := 0
			for _, i := range instances {
				if i.Label == st.Pending.Label {
					st.Pending.ID = i.ID
					count++
				}
			}
			if count != 1 {
				return errors.New("无法按标签唯一核实待建实例；保留记录，请在 Linode 核对，未重发创建请求")
			}
		}
		if err := s.saveRefill(st, "人工确认后恢复已记录实例；初始化脚本必须支持重复执行"); err != nil {
			return err
		}
		return s.finishRefill(ctx, st)
	}
	if err := s.validateRefill(&st.Config); err != nil {
		return err
	}
	st.Stage = "checking"
	if err := s.saveRefill(st, ""); err != nil {
		return err
	}
	if st.CurrentID > 0 {
		switchAccount, err := s.currentRefillAPI(ctx, st)
		if err != nil {
			return err
		}
		if !switchAccount {
			return nil
		}
	}
	firstBusy := -1
	for index := st.Cursor; index < len(st.Config.Accounts); index++ {
		account := st.Config.Accounts[index]
		available, ownerErr := s.accountAvailableForTask(st.TaskID, account)
		if ownerErr != nil {
			return ownerErr
		}
		if !available {
			if firstBusy < 0 {
				firstBusy = index
			}
			if err := s.saveRefill(st, "账号已被其他任务领取，跳过 "+account); err != nil {
				return err
			}
			continue
		}

		check, err := s.candidateRefillAPI(ctx, account)
		if err != nil {
			return err
		}
		if err := s.saveRefillCheck(st, check); err != nil {
			return err
		}
		if refillAuthFailure(check) {
			st.Cursor = index + 1
			if err := s.saveRefill(st, "候选账号 "+account+"："+check.Message+"，跳过"); err != nil {
				return err
			}
			continue
		}
		if check.Kind != "ok" {
			st.Stage = "api_wait"
			return s.saveRefill(st, "候选账号 "+account+"："+check.Message+"；保留队列位置，等待重试，未建机")
		}
		if check.Credit == nil || *check.Credit <= 0 {
			st.Cursor = index + 1
			if err := s.saveRefill(st, "候选账号无可用估算额度，跳过 "+account); err != nil {
				return err
			}
			continue
		}
		if err := s.saveRefill(st, "候选账号 API 认证、账号读取和实例列表权限检查通过；准备建机 "+account); err != nil {
			return err
		}
		// One persistent intent before POST. Unknown outcomes never create again.
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		password := "Aa9!" + base64.RawURLEncoding.EncodeToString(random)
		st.IPAttempts = 0
		st.Pending = &RefillPending{Account: account, Label: st.Config.Label + "-" + strconv.FormatInt(time.Now().UnixNano(), 36), Password: password}
		st.Stage = "creating"
		if err := s.saveRefill(st, "创建意图已加密保存；正在请求新实例"); err != nil {
			if errors.Is(err, errRefillOwned) {
				st.Pending = nil
				if firstBusy < 0 {
					firstBusy = index
				}
				if saveErr := s.saveRefill(st, "账号在预检后被其他任务领取，未发送建机请求"); saveErr != nil {
					return saveErr
				}
				continue
			}
			return err
		}

		data := map[string]any{"label": st.Pending.Label, "region": st.Config.Region, "type": st.Config.Type, "image": st.Config.Image, "root_pass": password, "booted": true, "tags": []string{"lnm-refill"}}
		payload, _ := json.Marshal(data)
		body, status, err := s.linodeFor(ctx, account, "POST", "/linode/instances", bytes.NewReader(payload))
		if err != nil {
			return errors.New("创建结果未知，已暂停；请按记录标签核对，禁止重复建机")
		}
		if status != 200 && status != 201 {
			if status == 429 {
				st.Pending = nil
				st.Stage = "api_wait"
				return s.saveRefill(st, "创建接口限流，保留当前候选账号，等待后重试；未切换其他账号")
			}

			if (status == 401 || status == 403) && validLinodeError(body) {
				st.Pending = nil
				st.Cursor = index + 1
				check.Status = status
				check.Kind = "auth_error"
				check.Message = "创建操作明确返回认证失败"
				if status == 403 {
					check.Kind = "permission_error"
					check.Message = "创建操作明确返回权限不足"
				}
				if err := s.saveRefillCheck(st, check); err != nil {
					return err
				}
				if err := s.saveRefill(st, fmt.Sprintf("建机明确返回 HTTP %d，跳过该账号；未将结果未知当作失败", status)); err != nil {
					return err
				}
				continue
			}

			if status >= 400 && status < 500 && status != 408 && status != 409 {
				st.Pending = nil
			}
			return fmt.Errorf("建机 HTTP %d，已保留意图供核对；未尝试其他账号", status)
		}
		var instance Instance
		if json.Unmarshal(body, &instance) != nil || instance.ID <= 0 || instance.Label != st.Pending.Label {
			return errors.New("建机响应不完整，已暂停并保留意图")
		}
		st.Pending.ID = instance.ID
		st.Cursor = index + 1
		if err := s.saveRefill(st, "实例已创建 #"+strconv.Itoa(instance.ID)); err != nil {
			return err
		}
		return s.finishRefill(ctx, st)
	}
	if firstBusy >= 0 {
		st.Cursor = firstBusy
		st.Stage = "account_wait"
		return s.saveRefill(st, "候选账号被其他任务占用，等待补充可用账号；未重复领取")
	}
	st.Config.Enabled = false
	st.Stage = "exhausted"
	return s.saveRefill(st, "账号队列已用完；暂停自动补号，原机保留")
}

func (s *Server) checkRefillChina(ctx context.Context, account string, id, port int) (Instance, error) {
	instance, err := s.waitRefillPort(ctx, account, id, port)
	if err != nil {
		return instance, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, err = s.checkDomesticTCP(ctx, publicIP(instance), port)
		if err == nil {
			return instance, nil
		}
		if !errors.Is(err, errDomesticTCPUnreachable) {
			return instance, err
		}
		if attempt < 2 {
			if err := s.refillDelay(ctx, 2*time.Second); err != nil {
				return instance, err
			}
		}
	}
	return instance, err
}
func (s *Server) refillDNS(ctx context.Context, domain string, instance Instance) error {
	if domain == "" {
		return nil
	}
	config, err := s.dnsConfigFor(domain)
	if err != nil || config == nil {
		return errors.New("接替 DNS 配置不可用")
	}
	if config.Provider == "cloudflare" {
		return s.syncCloudflare(ctx, *config, domain, publicIP(instance), strings.Split(instance.IPv6, "/")[0])
	}
	return s.syncAliDNS(ctx, *config, domain, publicIP(instance), strings.Split(instance.IPv6, "/")[0])
}
func (s *Server) finishRefill(ctx context.Context, st *RefillState) error {
	p := st.Pending
	if p == nil || p.ID <= 0 {
		return errors.New("没有可恢复的实例")
	}
	if err := s.saveRootPassword(p.Account, p.ID, p.Label, p.Password); err != nil {
		return errors.New("Root 密码保存失败；实例已保留")
	}
	instance, err := s.waitIPInstance(ctx, p.Account, p.ID, func(i Instance) bool { return i.Status == "running" && publicIP(i) != "" })
	if err != nil {
		return err
	}
	if instance.Label != p.Label {
		return errors.New("待接替实例的标签与创建意图不一致，已暂停")
	}
	st.Stage = "boot_check"
	if err := s.saveRefill(st, "等待 SSH 和开机 IP 检查"); err != nil {
		return err
	}
	if st.Config.BootCheck {
		instance, err = s.ensureRefillIP(ctx, st, p.Account, instance, st.Config.CheckPort)
		if err != nil {
			return err
		}
	}

	verifiedCredit, err := s.refillAccountCredit(ctx, p.Account)
	if err != nil {
		return err
	}
	if verifiedCredit <= 0 {
		return errors.New("目标账号额度不足，保留已创建实例并暂停接替")
	}
	st.Stage = "script"
	if err := s.saveRefill(st, "IP 检查完成，执行开机脚本（输出不写入操作日志，避免泄露脚本密钥）"); err != nil {
		return err
	}
	if err := s.runRefillBootScript(ctx, p.Account, instance, "export LNM_TASK_ID="+shellQuote(st.TaskID)+"\n"+st.Config.Script); err != nil {
		return err
	}
	st.Stage = "health"
	if err := s.saveRefill(st, "启动脚本已完成，检查业务端口"); err != nil {
		return err
	}
	instance, err = s.waitRefillPort(ctx, p.Account, p.ID, st.Config.HealthPort)
	if err != nil {
		return err
	}
	if st.Config.BootCheck {
		if _, err = s.checkRefillChina(ctx, p.Account, p.ID, st.Config.HealthPort); err != nil {
			return err
		}
	}
	st.Stage = "dns"
	if err := s.saveRefill(st, "健康检查通过，准备切换 DNS"); err != nil {
		return err
	}
	if err = s.refillDNS(ctx, st.Config.Domain, instance); err != nil {
		return errors.New("DNS 切换未全部完成；保留两台实例，请核对解析后恢复")
	}
	oldAccount, oldID := st.CurrentAccount, st.CurrentID
	if oldID > 0 && (oldID != p.ID || oldAccount != p.Account) {
		st.Retired = append(st.Retired, RefillRetired{Account: oldAccount, ID: oldID, IP: st.CurrentIP})
	}
	st.CurrentAccount = p.Account
	st.CurrentID = p.ID
	st.CurrentIP = publicIP(instance)
	for index, id := range st.Config.Accounts {
		if id == p.Account {
			st.Cursor = index + 1
			break
		}
	}
	st.Pending = nil
	st.CurrentCredit = &verifiedCredit
	st.APIFailures = 0
	st.LastAPIFailure = time.Time{}
	st.CreditAlerted = false
	st.Stage = "ready"
	if err := s.saveRefill(st, "接替成功，新 IP="+publicIP(instance)+"；旧实例未删除"); err != nil {
		return err
	}
	if oldID > 0 && st.Config.OldPolicy == "shutdown" {
		// New service is verified before asking Linode to stop the previous one.
		if err := s.ipJSON(ctx, oldAccount, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", oldID), map[string]any{}, nil); err != nil {
			return s.saveRefill(st, "新机已接替，但旧账号无法确认关机；旧机可能继续计费，请人工处理")
		}
		st.Retired[len(st.Retired)-1].ShutdownRequested = true
		return s.saveRefill(st, "旧机 #"+strconv.Itoa(oldID)+" 关机请求已接受；关机仍收取实例费用")
	}
	return nil
}

func (s *Server) refillInstanceAction(ctx context.Context, st *RefillState, action string) error {
	if st.CurrentID <= 0 {
		return errors.New("请先绑定或创建当前实例")
	}
	st.Stage = "running"
	if err := s.saveRefill(st, "开始实例操作："+action); err != nil {
		return err
	}
	instance, err := s.ipInstance(ctx, st.CurrentAccount, st.CurrentID)
	if err != nil {
		return err
	}
	switch action {
	case "probe":
		_, err = s.checkRefillChina(ctx, st.CurrentAccount, st.CurrentID, st.Config.CheckPort)
	case "boot":
		if instance.Status == "offline" {
			err = s.ipJSON(ctx, st.CurrentAccount, "POST", fmt.Sprintf("/linode/instances/%d/boot", st.CurrentID), map[string]any{}, nil)
			if err != nil {
				return err
			}
		}
		instance, err = s.waitIPInstance(ctx, st.CurrentAccount, st.CurrentID, func(i Instance) bool { return i.Status == "running" && publicIP(i) != "" })
		if err != nil {
			return err
		}
		if st.Config.BootCheck {
			instance, err = s.ensureRefillIP(ctx, st, st.CurrentAccount, instance, st.Config.CheckPort)
		}

	case "change-ip":
		instance, _, err = s.replaceIPFromBoot(ctx, st.CurrentAccount, instance, st.Config.CheckPort, "aliyun", true)
	default:
		return errors.New("不支持的实例操作")
	}
	if err != nil {
		return err
	}
	if action == "boot" {
		if err := s.saveRefill(st, "开机 IP 检查完成，执行开机脚本"); err != nil {
			return err
		}
		if err := s.runRefillBootScript(ctx, st.CurrentAccount, instance, "export LNM_TASK_ID="+shellQuote(st.TaskID)+"\n"+st.Config.Script); err != nil {
			return err
		}
		instance, err = s.waitRefillPort(ctx, st.CurrentAccount, st.CurrentID, st.Config.HealthPort)
		if err != nil {
			return err
		}
	}
	if action == "change-ip" || action == "boot" {
		if err := s.refillDNS(ctx, st.Config.Domain, instance); err != nil {
			return err
		}
	}
	st.CurrentIP = publicIP(instance)
	st.Stage = "ready"
	return s.saveRefill(st, "实例操作完成："+action+" IP="+st.CurrentIP)
}
func (s *Server) registerRefill(mux *http.ServeMux) {
	mux.HandleFunc("GET /refill", s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, refillPage)
	}))
	mux.HandleFunc("POST /api/accounts/{id}/api-check", s.auth(s.accountAPICheckAPI))
	mux.HandleFunc("GET /api/refill/tasks", s.auth(s.refillTasksAPI))
	mux.HandleFunc("POST /api/refill/tasks", s.auth(s.refillTasksAPI))
	mux.HandleFunc("GET /api/refill/tasks/{task}", s.auth(s.refillTaskAPI))
	mux.HandleFunc("PUT /api/refill/tasks/{task}", s.auth(s.refillTaskAPI))
	mux.HandleFunc("DELETE /api/refill/tasks/{task}", s.auth(s.refillTaskAPI))
	mux.HandleFunc("POST /api/refill/tasks/{task}/{action}", s.auth(s.refillTaskActionAPI))
	mux.HandleFunc("GET /api/refill", s.auth(s.refillAPI))
	mux.HandleFunc("PUT /api/refill", s.auth(s.refillAPI))
	mux.HandleFunc("POST /api/refill/{action}", s.auth(s.refillAPI))
	mux.HandleFunc("GET /api/instances/{id}/transfer", s.auth(s.instanceTransferAPI))
	mux.HandleFunc("GET /api/accounts/{id}/transfer", s.auth(s.accountTransferAPI))
}
func (s *Server) refillAPI(w http.ResponseWriter, r *http.Request) {
	r.SetPathValue("task", defaultRefillTask)
	if r.Method == "POST" {
		s.refillTaskActionAPI(w, r)
	} else {
		s.refillTaskAPI(w, r)
	}
}
func (s *Server) instanceTransferAPI(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	account := r.URL.Query().Get("account_id")
	if err != nil || id <= 0 || account == "" {
		fail(w, 400, "请选择账号和实例")
		return
	}
	s.transferResponse(w, r, account, fmt.Sprintf("/linode/instances/%d/transfer", id))
}
func (s *Server) accountTransferAPI(w http.ResponseWriter, r *http.Request) {
	s.transferResponse(w, r, r.PathValue("id"), "/account/transfer")
}
func (s *Server) transferResponse(w http.ResponseWriter, r *http.Request, account, path string) {
	body, status, err := s.linodeFor(useProxyContext(r.Context(), s.hasBoundProxy(account)), account, "GET", path, nil)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if status != 200 {
		fail(w, 502, fmt.Sprintf("流量查询 HTTP %d", status))
		return
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(body, &data) != nil {
		fail(w, 502, "流量数据无效")
		return
	}
	safe := map[string]json.RawMessage{}
	for _, key := range []string{"used", "quota", "billable", "bytes_in", "bytes_out", "bytes_total", "region_transfers"} {
		if value, ok := data[key]; ok {
			safe[key] = value
		}
	}
	send(w, 200, safe)
}
func (s *Server) hasBoundProxy(account string) bool {
	if s.credentials == nil {
		return false
	}
	_, ok := s.credentials.token("linode-proxy-" + account + "/0")
	return ok
}

func (s *Server) waitRefillPort(ctx context.Context, account string, id, port int) (Instance, error) {
	if s.refillWaitPort != nil {
		return s.refillWaitPort(ctx, account, id, port)
	}
	return s.waitBootProbePort(ctx, account, id, port)
}

// Retry only SSH readiness/system tuning, never the user's script.
func (s *Server) runRefillBootScript(ctx context.Context, account string, instance Instance, script string) error {
	if _, err := s.tuneNode(ctx, account, instance, false); err != nil {
		return errors.New("SSH 初始化失败，未切换入口")
	}
	command := "set -eu\nexport LNM_ACCOUNT_ID=" + shellQuote(account) + "\nexport LNM_INSTANCE_ID=" + strconv.Itoa(instance.ID) + "\nexport LNM_IPV4=" + shellQuote(publicIP(instance)) + "\n" + script + "\n"
	if _, err := s.deploySSH(ctx, account, instance, command); err != nil {
		return errors.New("开机脚本失败或执行结果未知；保留实例并暂停，需人工核对后恢复")
	}
	return nil
}
