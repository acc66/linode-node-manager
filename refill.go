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
	ReserveGB       float64  `json:"reserve_gb"`
	StopPercent     float64  `json:"stop_percent"`
	Enabled         bool     `json:"enabled"`
	Accounts        []string `json:"accounts"`
	Region          string   `json:"region"`
	Type            string   `json:"type"`
	Image           string   `json:"image"`
	Label           string   `json:"label"`
	Script          string   `json:"script"`
	Domain          string   `json:"domain"`
	CreditFloor     float64  `json:"credit_floor"`
	TransferPercent float64  `json:"transfer_percent"`
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
	Sample         *RefillSample   `json:"sample,omitempty"`
	Retired        []RefillRetired `json:"retired"`
	Config         RefillConfig    `json:"config"`
	CurrentAccount string          `json:"current_account"`
	CurrentID      int             `json:"current_instance"`
	CurrentIP      string          `json:"current_ip"`
	Cursor         int             `json:"cursor"`
	Stage          string          `json:"stage"`
	LastCheck      time.Time       `json:"last_check"`
	Pending        *RefillPending  `json:"pending,omitempty"`
	History        []RefillEvent   `json:"history"`
}

type RefillSample struct {
	Usage   RefillUsage `json:"usage"`
	At      time.Time   `json:"at"`
	Account string      `json:"account_id"`
}
type RefillUsage struct {
	ReserveGB   float64 `json:"reserve_gb"`
	Provisional bool    `json:"provisional"`
	Credit      float64 `json:"credit_usd"`
	Used        float64 `json:"used_gb"`
	Quota       float64 `json:"quota_gb"`
	Percent     float64 `json:"percent"`
}

func defaultRefillConfig() RefillConfig {
	return RefillConfig{ReserveGB: 20, Label: "refill-node", Image: "linode/debian12", CreditFloor: 1, TransferPercent: 90, IntervalMinutes: 5, BootCheck: true, AutoIP: true, CheckPort: 22, HealthPort: 22, OldPolicy: "keep"}
}
func (s *Server) loadRefill() (RefillState, error) {
	st := RefillState{Config: defaultRefillConfig(), Stage: "idle", History: []RefillEvent{}}
	if s.credentials == nil {
		return st, errors.New("请配置 ACCOUNT_ENCRYPTION_KEY 启用加密存储")
	}
	raw, ok := s.credentials.token("refill-state/0")
	if !ok {
		return st, nil
	}
	if json.Unmarshal([]byte(raw), &st) != nil {
		return st, errors.New("补号记录损坏，已停止自动操作")
	}
	return st, nil
}
func (s *Server) saveRefill(st *RefillState, message string) error {
	if message != "" {
		st.History = append(st.History, RefillEvent{At: time.Now().UTC().Format(time.RFC3339), Message: message})
	}
	if len(st.History) > 200 {
		st.History = st.History[len(st.History)-200:]
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.saveRootPassword("refill-state", 0, "Refill workflow", string(raw))
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
	if math.IsNaN(c.CreditFloor) || math.IsInf(c.CreditFloor, 0) || c.CreditFloor < 0 || c.CreditFloor > 10000 || c.TransferPercent < 1 || c.TransferPercent > 95 || math.IsNaN(c.TransferPercent) {
		return errors.New("额度阈值无效；流量阈值须在 1%-95%")
	}
	if c.IntervalMinutes < 1 || c.IntervalMinutes > 60 || c.CheckPort < 1 || c.CheckPort > 65535 || c.HealthPort < 1 || c.HealthPort > 65535 {
		return errors.New("检查间隔或端口无效")
	}
	if c.ReserveGB < 0 || c.ReserveGB > 1000000 || math.IsNaN(c.ReserveGB) || math.IsInf(c.ReserveGB, 0) || c.StopPercent != 0 && (c.StopPercent <= c.TransferPercent || c.StopPercent > 99) {
		return errors.New("流量预留或紧急停机阈值无效，停机阈值须高于接替阈值且不超过 99%")
	}
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

func (s *Server) refillUsage(ctx context.Context, account, region string) (RefillUsage, error) {
	return s.refillUsageFor(ctx, account, region, false)
}
func (s *Server) refillUsageFor(ctx context.Context, account, region string, fresh bool) (RefillUsage, error) {
	var usage RefillUsage

	regionBody, regionStatus, regionErr := s.linodeFor(ctx, account, "GET", "/regions/"+region, nil)
	var regionInfo struct {
		ID   string `json:"id"`
		Site string `json:"site_type"`
	}
	if regionErr != nil {
		return usage, regionErr
	}
	if regionStatus != 200 || json.Unmarshal(regionBody, &regionInfo) != nil || regionInfo.ID != region || regionInfo.Site != "core" {
		return usage, errors.New("当前自动接替仅支持已核实的 core 地区流量池；未将其他地区用量误计入全局池")
	}
	body, status, err := s.linodeFor(ctx, account, "GET", "/account", nil)
	if err != nil {
		return usage, err
	}
	if status != 200 {
		return usage, fmt.Errorf("账号额度查询 HTTP %d，未切换账号", status)
	}
	usage.Credit, err = refillCredit(body, time.Now().UTC())
	if err != nil {
		return usage, err
	}
	body, status, err = s.linodeFor(ctx, account, "GET", "/account/transfer", nil)
	if err != nil {
		return usage, err
	}
	if status != 200 {
		return usage, fmt.Errorf("账号流量查询 HTTP %d", status)
	}
	var transfer struct {
		Used    *float64 `json:"used"`
		Quota   *float64 `json:"quota"`
		Regions []struct {
			ID    string   `json:"id"`
			Used  *float64 `json:"used"`
			Quota *float64 `json:"quota"`
		} `json:"region_transfers"`
	}
	if json.Unmarshal(body, &transfer) != nil {
		return usage, errors.New("流量响应格式无效")
	}
	used, quota := transfer.Used, transfer.Quota
	for _, r := range transfer.Regions {
		if r.ID == region {
			used, quota = r.Used, r.Quota
			break
		}
	}
	if fresh && used != nil && quota != nil && *used == 0 && *quota == 0 {
		usage.Provisional = true
		return usage, nil
	}
	if used == nil || quota == nil || *used < 0 || *quota <= 0 {
		return usage, errors.New("未取得有效流量池配额，不能假定新账号拥有 1TB")
	}
	usage.Used = *used
	usage.Quota = *quota
	usage.Percent = *used / *quota * 100
	return usage, nil
}
func (s *Server) refillReady(c RefillConfig, u RefillUsage) bool {
	return u.Credit > c.CreditFloor && u.Percent < c.TransferPercent && (u.Provisional || u.Quota-u.Used > math.Max(c.ReserveGB, u.ReserveGB))
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
		currentInstance, lookupErr := s.ipInstance(ctx, st.CurrentAccount, st.CurrentID)
		if lookupErr != nil {
			return lookupErr
		}
		usage, err := s.refillUsage(ctx, st.CurrentAccount, currentInstance.Region)
		if err != nil {
			return err
		}

		usage.ReserveGB = st.Config.ReserveGB
		if prior := st.Sample; prior != nil && prior.Account == st.CurrentAccount && prior.At.UTC().Format("2006-01") == time.Now().UTC().Format("2006-01") {
			seconds := time.Since(prior.At).Seconds()
			if seconds >= 1 && usage.Used >= prior.Usage.Used {
				usage.ReserveGB = math.Max(usage.ReserveGB, (usage.Used-prior.Usage.Used)/seconds*1800)
			}
		}
		st.Sample = &RefillSample{Usage: usage, At: time.Now().UTC(), Account: st.CurrentAccount}
		if s.refillReady(st.Config, usage) {
			st.Stage = "ready"
			return s.saveRefill(st, fmt.Sprintf("检查完成：估算额度 $%.2f，流量 %.2f/%.2f GB (%.1f%%)", usage.Credit, usage.Used, usage.Quota, usage.Percent))
		}
		if err := s.saveRefill(st, "当前账号额度或流量达到阈值，查找后续账号"); err != nil {
			return err
		}
	}
	for index := st.Cursor; index < len(st.Config.Accounts); index++ {
		account := st.Config.Accounts[index]
		usage, err := s.refillUsageFor(ctx, account, st.Config.Region, true)
		if err != nil {
			return err
		}
		if !s.refillReady(st.Config, usage) {
			st.Cursor = index + 1
			if err := s.saveRefill(st, "跳过额度或流量不足的账号 "+account); err != nil {
				return err
			}
			continue
		}
		planBody, planStatus, planErr := s.linodeFor(ctx, account, "GET", "/linode/types/"+st.Config.Type, nil)
		var plan struct {
			Transfer *float64 `json:"transfer"`
		}
		if planErr != nil {
			return planErr
		}
		if planStatus != 200 || json.Unmarshal(planBody, &plan) != nil || plan.Transfer == nil || *plan.Transfer <= 0 {
			return errors.New("所选套餐没有可核实的赠送流量，未创建实例")
		}
		// One persistent intent before POST. Unknown outcomes never create again.
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		password := "Aa9!" + base64.RawURLEncoding.EncodeToString(random)
		st.Pending = &RefillPending{Account: account, Label: st.Config.Label + "-" + strconv.FormatInt(time.Now().UnixNano(), 36), Password: password}
		st.Stage = "creating"
		if err := s.saveRefill(st, "创建意图已加密保存；正在请求新实例"); err != nil {
			return err
		}
		data := map[string]any{"label": st.Pending.Label, "region": st.Config.Region, "type": st.Config.Type, "image": st.Config.Image, "root_pass": password, "booted": true, "tags": []string{"lnm-refill"}}
		payload, _ := json.Marshal(data)
		body, status, err := s.linodeFor(ctx, account, "POST", "/linode/instances", bytes.NewReader(payload))
		if err != nil {
			return errors.New("创建结果未知，已暂停；请按记录标签核对，禁止重复建机")
		}
		if status != 200 && status != 201 {
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
	s.refillEmergencyStop(ctx, st)
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
			select {
			case <-ctx.Done():
				return instance, ctx.Err()
			case <-time.After(2 * time.Second):
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
		instance, err = s.checkRefillChina(ctx, p.Account, p.ID, st.Config.CheckPort)
		if errors.Is(err, errDomesticTCPUnreachable) && st.Config.AutoIP {
			if err := s.saveRefill(st, "国内连续三次不通，尝试一次原机换 IP"); err != nil {
				return err
			}
			instance, _, err = s.replaceIPFromBoot(ctx, p.Account, instance, st.Config.CheckPort, "aliyun", true)
		}
		if err != nil {
			return err
		}
	}

	var verifiedUsage RefillUsage
	for attempt := 0; attempt < 12; attempt++ {
		verifiedUsage, err = s.refillUsage(ctx, p.Account, st.Config.Region)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "未取得有效流量池配额") {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	if err != nil {
		return err
	}
	if !s.refillReady(st.Config, verifiedUsage) {
		return errors.New("新机创建后账号额度或实际流量池不足，保留新机但不切换业务")
	}
	st.Stage = "script"
	if err := s.saveRefill(st, "执行首次初始化脚本（输出不写入操作日志，避免泄露脚本密钥）"); err != nil {
		return err
	}
	// Only SSH readiness may be retried. Never retry a user script automatically.
	if _, err := s.tuneNode(ctx, p.Account, instance, false); err != nil {
		return errors.New("SSH 初始化失败；保留新机，未切换入口")
	}
	script := "set -eu\nexport LNM_ACCOUNT_ID=" + shellQuote(p.Account) + "\nexport LNM_INSTANCE_ID=" + strconv.Itoa(p.ID) + "\nexport LNM_IPV4=" + shellQuote(publicIP(instance)) + "\n" + st.Config.Script + "\n"
	if _, err := s.deploySSH(ctx, p.Account, instance, script); err != nil {
		return errors.New("启动脚本失败或执行结果未知；保留新机与原机，需人工核对后恢复")
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
	st.Sample = nil
	st.Stage = "ready"
	if err := s.saveRefill(st, "接替成功，新 IP="+publicIP(instance)+"；旧实例未删除"); err != nil {
		return err
	}
	if oldID > 0 && st.Config.OldPolicy == "shutdown" {
		// New service is verified before asking Linode to stop the previous one.
		if err := s.ipJSON(ctx, oldAccount, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", oldID), map[string]any{}, nil); err != nil {
			return errors.New("新机已接替，但旧机关机结果未确认；请人工检查以防继续跑流量")
		}
		st.Retired[len(st.Retired)-1].ShutdownRequested = true
		return s.saveRefill(st, "旧机 #"+strconv.Itoa(oldID)+" 关机请求已接受；关机仍收取实例费用")
	}
	return nil
}

func (s *Server) refillWorker(resume bool, action string) {
	defer s.refillMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	st, err := s.loadRefill()
	if err != nil {
		return
	}
	if action != "" {
		err = s.refillInstanceAction(refillContext(ctx), &st, action)
	} else {
		err = s.runRefill(ctx, &st, resume)
	}
	if err != nil {
		if action == "" {
			s.refillEmergencyStop(refillContext(ctx), &st)
		}
		st.Config.Enabled = false
		st.Stage = "failed"
		if saveErr := s.saveRefill(&st, err.Error()); saveErr != nil {
			return
		}
		go s.telegram("Linode 自动运维已暂停：" + err.Error())
	}
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
			instance, err = s.checkRefillChina(ctx, st.CurrentAccount, st.CurrentID, st.Config.CheckPort)
			if errors.Is(err, errDomesticTCPUnreachable) && st.Config.AutoIP {
				instance, _, err = s.replaceIPFromBoot(ctx, st.CurrentAccount, instance, st.Config.CheckPort, "aliyun", true)
			}
		}
	case "change-ip":
		instance, _, err = s.replaceIPFromBoot(ctx, st.CurrentAccount, instance, st.Config.CheckPort, "aliyun", true)
	default:
		return errors.New("不支持的实例操作")
	}
	if err != nil {
		return err
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
func (s *Server) refillScheduler(ctx context.Context) {
	// A crash during a mutation must never silently replay a create or script.
	if s.refillMu.TryLock() {
		st, err := s.loadRefill()
		if err == nil && st.Stage != "idle" && st.Stage != "ready" && st.Stage != "failed" && st.Stage != "exhausted" {
			st.Config.Enabled = false
			st.Stage = "interrupted"
			_ = s.saveRefill(&st, "进程重启时发现未完成操作，已暂停；请核对后恢复")
		}
		s.refillMu.Unlock()
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.refillMu.TryLock() {
				continue
			}
			st, err := s.loadRefill()
			if err != nil || !st.Config.Enabled || st.Pending != nil || time.Since(st.LastCheck) < time.Duration(st.Config.IntervalMinutes)*time.Minute {
				s.refillMu.Unlock()
				continue
			}
			go s.refillWorker(false, "")
		}
	}
}
func (s *Server) registerRefill(mux *http.ServeMux) {
	mux.HandleFunc("GET /refill", s.auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, refillPage)
	}))
	mux.HandleFunc("GET /api/refill", s.auth(s.refillAPI))
	mux.HandleFunc("PUT /api/refill", s.auth(s.refillAPI))
	mux.HandleFunc("POST /api/refill/{action}", s.auth(s.refillAPI))
	mux.HandleFunc("GET /api/instances/{id}/transfer", s.auth(s.instanceTransferAPI))
	mux.HandleFunc("GET /api/accounts/{id}/transfer", s.auth(s.accountTransferAPI))
}
func (s *Server) refillAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		st, err := s.loadRefill()
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		if st.Pending != nil {
			st.Pending.Password = ""
		}
		busy := !s.refillMu.TryLock()
		if !busy {
			s.refillMu.Unlock()
		}
		send(w, 200, map[string]any{"state": st, "busy": busy})
		return
	}
	if !s.refillMu.TryLock() {
		fail(w, 409, "运维任务正在运行，请等待后再操作")
		return
	}
	handedOff := false
	defer func() {
		if !handedOff {
			s.refillMu.Unlock()
		}
	}()
	st, err := s.loadRefill()
	if err != nil {
		fail(w, 503, err.Error())
		return
	}
	if r.Method == "PUT" {
		var in struct {
			Config   RefillConfig `json:"config"`
			Account  string       `json:"current_account"`
			Instance int          `json:"current_instance"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
			fail(w, 400, "配置格式无效")
			return
		}
		if st.Pending != nil {
			fail(w, 409, "存在未完成建机，请先恢复并核对")
			return
		}
		if err = s.validateRefill(&in.Config); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if in.Instance < 0 {
			fail(w, 400, "实例 ID 无效")
			return
		}
		if in.Instance > 0 {
			matched := false
			for _, id := range in.Config.Accounts {
				if id == in.Account {
					matched = true
				}
			}
			if !matched {
				fail(w, 400, "当前账号不在队列中")
				return
			}
			// Binding a current instance is read-only, but always uses its fixed proxy.
			instance, lookupErr := s.ipInstance(refillContext(r.Context()), in.Account, in.Instance)
			if lookupErr != nil {
				fail(w, 400, "无法核实当前实例")
				return
			}
			st.CurrentIP = publicIP(instance)
		} else {
			in.Account = ""
			st.CurrentIP = ""
		}
		st.Config = in.Config
		st.CurrentAccount = in.Account
		st.CurrentID = in.Instance
		st.Stage = "idle"
		st.Cursor = 0
		for i, id := range st.Config.Accounts {
			if id == st.CurrentAccount && st.CurrentID > 0 {
				st.Cursor = i + 1
			}
		}
		err = s.saveRefill(&st, "配置已加密保存；自动补号="+strconv.FormatBool(st.Config.Enabled))
		if err != nil {
			fail(w, 500, "配置保存失败")
			return
		}
		send(w, 200, map[string]bool{"saved": true})
		return
	}
	action := r.PathValue("action")
	if action == "pause" {
		st.Config.Enabled = false
		if err = s.saveRefill(&st, "已暂停自动补号"); err != nil {
			fail(w, 500, "暂停保存失败")
			return
		}
		send(w, 200, map[string]bool{"paused": true})
		return
	}
	var confirm struct {
		Billing bool `json:"confirm_billing"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&confirm) != nil {
		fail(w, 400, "请求格式无效")
		return
	}
	if action != "probe" && !confirm.Billing {
		fail(w, 400, "请确认实例及 IPv4 的费用")
		return
	}
	if action != "run" && action != "resume" && action != "probe" && action != "change-ip" && action != "boot" {
		fail(w, 404, "未知操作")
		return
	}
	if st.Pending != nil && action != "resume" {
		fail(w, 409, "已有未完成建机记录，只能核对后恢复")
		return
	}
	if action == "resume" && st.Pending == nil {
		fail(w, 409, "没有未完成建机记录")
		return
	}
	if action == "probe" || action == "change-ip" || action == "boot" {
		if st.CurrentID <= 0 {
			fail(w, 400, "请先绑定当前实例")
			return
		}
		if !s.chinaProbeConfigured("aliyun") {
			fail(w, 409, "请先配置阿里云国内探测机")
			return
		}
	}
	handedOff = true
	if action == "run" || action == "resume" {
		go s.refillWorker(action == "resume", "")
	} else {
		go s.refillWorker(false, action)
	}
	send(w, 202, map[string]string{"status": "queued"})
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
func (s *Server) refillMutationBusy() bool {
	if !s.refillMu.TryLock() {
		return true
	}
	s.refillMu.Unlock()
	return false
}

// Optional circuit breaker: stop the current VM only on a fresh, confirmed
// account-pool reading. It deliberately trades availability for a cost ceiling.
func (s *Server) refillEmergencyStop(ctx context.Context, st *RefillState) {
	if st.Config.StopPercent == 0 || st.CurrentID <= 0 {
		return
	}
	current, lookupErr := s.ipInstance(ctx, st.CurrentAccount, st.CurrentID)
	if lookupErr != nil {
		return
	}
	usage, err := s.refillUsage(ctx, st.CurrentAccount, current.Region)
	if err != nil || usage.Percent < st.Config.StopPercent {
		return
	}
	if err = s.saveRefill(st, "流量达到已配置紧急上限，准备关闭当前实例以停止继续跑流量"); err != nil {
		return
	}
	err = s.ipJSON(ctx, st.CurrentAccount, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", st.CurrentID), map[string]any{}, nil)
	text := "紧急关机请求已接受；实例费用继续产生"
	if err != nil {
		text = "紧急关机结果未确认，请立即人工处理"
	}
	_ = s.saveRefill(st, text)
}
