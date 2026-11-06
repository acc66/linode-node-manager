package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IPPlan struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Class string `json:"class"`
	Price struct {
		Hourly  float64 `json:"hourly"`
		Monthly float64 `json:"monthly"`
	} `json:"price"`
}
type IPChange struct {
	Job                Job      `json:"job"`
	Original           Instance `json:"original"`
	Plan               string   `json:"plan"`
	HelperLabel        string   `json:"helper_label"`
	HelperID           int      `json:"helper_id"`
	HelperCleaned      bool     `json:"helper_cleaned"`
	SwapAttempted      bool     `json:"swap_attempted"`
	SwapVerified       bool     `json:"swap_verified"`
	UseProxy           bool     `json:"use_proxy"`
	CheckPort          int      `json:"check_port,omitempty"`
	CheckChinaOriginal bool     `json:"check_china_original,omitempty"`
	ChinaProbe         bool     `json:"china_probe,omitempty"`
	ChinaProvider      string   `json:"china_provider,omitempty"`
}

func (s *Server) ipJSON(ctx context.Context, account, method, path string, input, output any) error {
	var body *bytes.Reader
	data := []byte(nil)
	if input != nil {
		data, _ = json.Marshal(input)
	}
	body = bytes.NewReader(data)
	b, status, err := s.linodeFor(ctx, account, method, path, body)
	if err != nil {
		return errors.New("Linode 请求结果未知，请刷新核对，勿重复提交")
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Linode %s HTTP %d，请检查权限、配额和资源状态", method, status)
	}
	if output != nil {
		if json.Unmarshal(b, output) != nil {
			return errors.New("Linode 响应无效")
		}
	}
	return nil
}
func (s *Server) ipInstance(ctx context.Context, account string, id int) (Instance, error) {
	var i Instance
	err := s.ipJSON(ctx, account, "GET", "/linode/instances/"+strconv.Itoa(id), nil, &i)
	if err == nil && i.ID != id {
		err = errors.New("实例响应 ID 不匹配")
	}
	i.AccountID = account
	return i, err
}
func (s *Server) checkIPTarget(ctx context.Context, account string, i Instance) error {
	if i.Status != "running" && i.Status != "offline" {
		return errors.New("实例必须处于运行或关机状态")
	}
	if i.Region == "" || publicIP(i) == "" || len(i.IPv4) != 1 {
		return errors.New("当前换 IP 仅支持单公网 IPv4、无附加私网 IPv4 的实例")
	}
	var ip struct {
		LinodeID int  `json:"linode_id"`
		Reserved bool `json:"reserved"`
		Public   bool `json:"public"`
	}
	if err := s.ipJSON(ctx, account, "GET", "/networking/ips/"+url.PathEscape(publicIP(i)), nil, &ip); err != nil {
		return err
	}
	if ip.LinodeID != i.ID || !ip.Public || ip.Reserved {
		return errors.New("IPv4 必须属于目标实例且不是预留 IP；预留/共享 IP 不自动交换")
	}
	if i.InterfaceGeneration == "linode" {
		var settings struct {
			NetworkHelper bool `json:"network_helper"`
		}
		if err := s.ipJSON(ctx, account, "GET", fmt.Sprintf("/linode/instances/%d/interfaces/settings", i.ID), nil, &settings); err != nil {
			return err
		}
		if !settings.NetworkHelper {
			return errors.New("请先为原机启用 Network Helper，避免换 IP 后网络失联")
		}
	} else {
		var configs struct {
			Data []struct {
				Helpers struct {
					Network bool `json:"network"`
				} `json:"helpers"`
			} `json:"data"`
		}
		if err := s.ipJSON(ctx, account, "GET", fmt.Sprintf("/linode/instances/%d/configs", i.ID), nil, &configs); err != nil {
			return err
		}
		if len(configs.Data) == 0 {
			return errors.New("原机没有可用的启动配置")
		}
		for _, config := range configs.Data {
			if !config.Helpers.Network {
				return errors.New("原机存在未启用 Network Helper 的启动配置，请先确认网络配置")
			}
		}
	}
	return nil
}
func (s *Server) saveIPChange(op *IPChange) error {
	op.Job.HelperID = op.HelperID
	op.Job.HelperCleaned = op.HelperCleaned
	raw, _ := json.Marshal(op)
	if err := s.saveRootPassword("ip-job-"+op.Job.ID, 0, "IP change", string(raw)); err != nil {
		return err
	}
	s.mu.Lock()
	s.jobs[op.Job.ID] = op.Job
	s.mu.Unlock()
	return nil
}
func (s *Server) loadIPChange(id string) (*IPChange, error) {
	if s.credentials == nil {
		return nil, errors.New("换 IP 任务不存在")
	}
	raw, ok := s.credentials.token("ip-job-" + id + "/0")
	if !ok {
		return nil, errors.New("换 IP 任务不存在")
	}
	var op IPChange
	if json.Unmarshal([]byte(raw), &op) != nil || op.Job.ID != id || op.Job.Kind != "ip_change" {
		return nil, errors.New("换 IP 任务数据无效")
	}
	return &op, nil
}
func (s *Server) ipJobLog(op *IPChange, line string) {
	op.Job.Log += time.Now().UTC().Format("15:04:05") + " " + line + "\n"
	_ = s.saveIPChange(op)
}
func (s *Server) waitIPInstance(ctx context.Context, account string, id int, predicate func(Instance) bool) (Instance, error) {
	poll, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		instance, err := s.ipInstance(poll, account, id)
		if err != nil {
			return instance, err
		}
		if predicate(instance) {
			return instance, nil
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-poll.Done():
			timer.Stop()
			return instance, errors.New("等待 Linode 状态超时")
		case <-timer.C:
		}
	}
}
func (s *Server) cleanupIPHelper(ctx context.Context, op *IPChange) error {
	if op.HelperID == 0 || op.HelperCleaned {
		return nil
	}
	if op.HelperID == op.Original.ID {
		return errors.New("拒绝清理：临时实例 ID 与原机相同")
	}
	var helper Instance
	b, status, err := s.linodeFor(ctx, op.Job.AccountID, "GET", fmt.Sprintf("/linode/instances/%d", op.HelperID), nil)
	if err == nil && status == 404 {
		op.HelperCleaned = true
		return s.saveIPChange(op)
	}
	if err != nil || status != 200 || json.Unmarshal(b, &helper) != nil {
		return errors.New("无法核实临时实例，未删除，请稍后清理")
	}
	if helper.ID != op.HelperID || helper.Label != op.HelperLabel || helper.Image != "" || helper.Status != "offline" {
		return errors.New("临时实例身份或状态发生变化，未自动删除，请人工核对")
	}
	original, err := s.ipInstance(ctx, op.Job.AccountID, op.Original.ID)
	if err != nil || publicIP(original) == "" {
		return errors.New("无法确认原机仍有公网 IPv4，暂不删除临时实例")
	}
	if err := s.ipJSON(ctx, op.Job.AccountID, "DELETE", fmt.Sprintf("/linode/instances/%d", op.HelperID), nil, nil); err != nil {
		return err
	}
	op.HelperCleaned = true
	return s.saveIPChange(op)
}
func (s *Server) runIPChangeUsingHelper(ctx context.Context, op *IPChange) (runErr error) {
	op.Job.Status = "running"
	if err := s.saveIPChange(op); err != nil {
		return err
	}
	account := op.Job.AccountID
	oldIP := publicIP(op.Original)
	defer func() {
		recovery, cancel := context.WithTimeout(useProxyContext(context.Background(), op.UseProxy), 3*time.Minute)
		defer cancel()
		if op.HelperID > 0 && (!op.SwapAttempted || op.SwapVerified) {
			if err := s.cleanupIPHelper(recovery, op); err != nil {
				s.ipJobLog(op, fmt.Sprintf("临时实例 #%d 清理未完成：%s；可能继续计费，请使用清理按钮。", op.HelperID, err))
				if runErr == nil {
					runErr = err
				}
			} else {
				s.ipJobLog(op, fmt.Sprintf("临时实例 #%d 已清理，未删除原机。", op.HelperID))
			}
		}
		if op.HelperID > 0 && !op.HelperCleaned {
			s.ipJobLog(op, fmt.Sprintf("保留临时实例 #%d（%s），请核对 IP 分配后清理，避免持续计费。", op.HelperID, op.HelperLabel))
		}
		if runErr != nil {
			op.Job.Status = "failed"
			s.ipJobLog(op, "换 IP 流程未全部完成："+runErr.Error())
		} else {
			op.Job.Status = "success"
			s.ipJobLog(op, "换 IP 完成；原机 ID、磁盘、配置保留。新 IP 是否可从你的网络访问，需要客户端验证。")
		}
		_ = s.saveIPChange(op)
	}()
	source, err := s.ipInstance(ctx, account, op.Original.ID)
	if err != nil {
		return err
	}
	if publicIP(source) != oldIP || source.Region != op.Original.Region || source.Status != op.Original.Status {
		return errors.New("原机 IP 或状态已变化，请重新打开换 IP 页面")
	}
	s.ipJobLog(op, fmt.Sprintf("保留原机 #%d，旧 IPv4=%s，同地区=%s，临时套餐=%s。", source.ID, oldIP, source.Region, op.Plan))
	payload := map[string]any{"label": op.HelperLabel, "region": source.Region, "type": op.Plan, "booted": false, "backups_enabled": false, "tags": []string{"lnm-ip-helper"}}
	if err := s.openNetworkConfig(ctx, account, payload); err != nil {
		return err
	}
	// Never retry a create with an unknown response: it may have incurred charges.
	s.ipJobLog(op, "创建不安装系统、不启动的临时实例（会按所选套餐计费）…")
	var helper Instance
	if err := s.ipJSON(ctx, account, "POST", "/linode/instances", payload, &helper); err != nil {
		return fmt.Errorf("%w；如结果未知请按标签 %s 在 Linode 核对临时实例", err, op.HelperLabel)
	}
	if helper.ID <= 0 || helper.ID == source.ID {
		return errors.New("临时实例响应 ID 无效，请在 Linode 核对标签 " + op.HelperLabel)
	}
	op.HelperID = helper.ID
	if err := s.saveIPChange(op); err != nil {
		return errors.New("无法保存临时实例记录，将尝试清理")
	}
	helper, err = s.waitIPInstance(ctx, account, helper.ID, func(i Instance) bool { return publicIP(i) != "" && i.Status == "offline" })
	if err != nil {
		return err
	}
	newIP := publicIP(helper)
	if newIP == oldIP {
		return errors.New("临时实例未获得不同的 IPv4")
	}
	op.Job.OldIP = oldIP
	op.Job.NewIP = newIP
	s.ipJobLog(op, fmt.Sprintf("临时实例 #%d，新 IPv4=%s。", helper.ID, newIP))
	wasRunning := source.Status == "running"
	stopped := false
	defer func() {
		if runErr != nil && wasRunning && stopped && (!op.SwapAttempted || op.SwapVerified) {
			recovery, cancel := context.WithTimeout(useProxyContext(context.Background(), op.UseProxy), time.Minute)
			defer cancel()
			if err := s.ipJSON(recovery, account, "POST", fmt.Sprintf("/linode/instances/%d/boot", source.ID), map[string]any{}, nil); err != nil {
				s.ipJobLog(op, "恢复原机开机未确认，请在实例列表核对状态。")
			} else {
				s.ipJobLog(op, "已请求恢复原机开机。")
			}
		}
	}()
	if wasRunning {
		stopped = true
		s.ipJobLog(op, "关闭原机以刷新网络配置，原机磁盘和后端不重建。")
		if err := s.ipJSON(ctx, account, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", source.ID), map[string]any{}, nil); err != nil {
			return err
		}
		stopped = true
		if _, err := s.waitIPInstance(ctx, account, source.ID, func(i Instance) bool { return i.Status == "offline" }); err != nil {
			return err
		}
	}
	op.SwapAttempted = true
	if err := s.saveIPChange(op); err != nil {
		op.SwapAttempted = false
		return err
	}
	s.ipJobLog(op, fmt.Sprintf("交换公网 IPv4：原机 #%d ← %s；临时实例 #%d ← %s。", source.ID, newIP, helper.ID, oldIP))
	swap := map[string]any{"region": source.Region, "assignments": []map[string]any{{"address": newIP, "linode_id": source.ID}, {"address": oldIP, "linode_id": helper.ID}}}
	swapErr := s.ipJSON(ctx, account, "POST", "/networking/ips/assign", swap, nil)
	// An API timeout is not proof of failure. Read both assignments before cleanup.
	original, verifyErr := s.ipInstance(ctx, account, source.ID)
	helperNow, helperErr := s.ipInstance(ctx, account, helper.ID)
	if verifyErr != nil || helperErr != nil {
		return errors.New("交换结果无法核实，未删除临时实例；请核对两台实例的 IP")
	}
	if publicIP(original) == oldIP && publicIP(helperNow) == newIP {
		op.SwapAttempted = false
		if swapErr != nil {
			return swapErr
		}
		return errors.New("交换尚未生效，未报告成功，请稍后重新核对")
	}
	if publicIP(original) != newIP || publicIP(helperNow) != oldIP {
		return errors.New("IP 分配与预期不同，未自动清理，请人工核对")
	}
	op.SwapVerified = true
	op.Job.IPChanged = true
	if err := s.saveIPChange(op); err != nil {
		return err
	}
	if err := moveBootstrapHostKey(oldIP, newIP); err != nil {
		s.ipJobLog(op, "SSH 主机密钥缓存更新失败；后续 SSH 可能需要核对指纹："+err.Error())
	}
	if wasRunning {
		s.ipJobLog(op, "新 IPv4 已确认，恢复原机开机，由 Network Helper 更新系统网络。")
		if err := s.ipJSON(ctx, account, "POST", fmt.Sprintf("/linode/instances/%d/boot", source.ID), map[string]any{}, nil); err != nil {
			return err
		}
		stopped = false
		original, err = s.waitIPInstance(ctx, account, source.ID, func(i Instance) bool { return i.Status == "running" && publicIP(i) == newIP })
		if err != nil {
			return err
		}
	}
	if wasRunning && s.canTune(account, source.ID) {
		s.ipJobLog(op, "通过新 IP 验证 SSH，并应用持久 BBR/nofile 设置…")
		output, tuneErr := s.tuneNode(ctx, account, original, s.openPortsSaved(account, source.ID))
		s.ipJobLog(op, output)
		if tuneErr != nil {
			s.ipJobLog(op, "新 IP 的 SSH/优化暂未验证成功："+tuneErr.Error())
		}
	}
	if op.Job.TargetID > 0 {
		s.ipJobLog(op, "更新绑定 wp2 节点的 DNS…")
		ready, log, err := s.prepareDeploymentDNS(ctx, env("WP2_BASE_URL", ""), env("WP2_API_TOKEN", ""), op.Job.TargetID, &original)
		s.ipJobLog(op, log)
		if err != nil {
			op.Job.DNSStatus = "failed"
			return fmt.Errorf("原机 IP 已更换，但 DNS 未完成：%w", err)
		}
		op.Job.DNSStatus = "skipped"
		if ready {
			op.Job.DNSStatus = "updated"
		}
	} else {
		op.Job.DNSStatus = "skipped"
		s.ipJobLog(op, "未选择/保存 wp2 节点绑定，DNS 未自动更新，请按新 IP 核对连接域名。")
	}
	s.mu.Lock()
	delete(s.status, source.ID)
	delete(s.accountStatus, account+"/"+strconv.Itoa(source.ID))
	s.mu.Unlock()
	return nil
}
func moveBootstrapHostKey(oldIP, newIP string) error {
	dir := env("SSH_BOOTSTRAP_DIR", "/data/ssh-bootstrap")
	path := filepath.Join(dir, "known_hosts")
	keys := []string{}
	seen := map[string]bool{}
	for _, source := range []string{path, env("SSH_KNOWN_HOSTS_PATH", "/run/secrets/known_hosts")} {
		if _, err := os.Stat(source); err != nil {
			continue
		}
		output, _ := exec.Command("ssh-keygen", "-F", oldIP, "-f", source).Output()
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				key := newIP + " " + strings.Join(fields[1:], " ")
				if !seen[key] {
					keys = append(keys, key)
					seen[key] = true
				}
			}
		}
	}
	if len(keys) == 0 {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			return err
		}
	}
	for _, address := range []string{oldIP, newIP} {
		if err := exec.Command("ssh-keygen", "-R", address, "-f", path).Run(); err != nil {
			return errors.New("无法更新 known_hosts")
		}
	}
	if len(keys) > 0 {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(strings.Join(keys, "\n") + "\n")
		return err
	}
	return nil
}
func (s *Server) ipChangePlanAPI(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account_id")
	id, err := strconv.Atoi(r.PathValue("id"))
	if account == "" || err != nil || id <= 0 {
		fail(w, 400, "请选择具体账号和实例")
		return
	}
	instance, err := s.ipInstance(r.Context(), account, id)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if err := s.checkIPTarget(r.Context(), account, instance); err != nil {
		fail(w, 409, err.Error())
		return
	}
	bound := 0
	if s.credentials != nil {
		if raw, ok := s.credentials.token("node-binding-" + account + "/" + strconv.Itoa(id)); ok {
			bound, _ = strconv.Atoi(raw)
		}
	}
	send(w, 200, map[string]any{"instance": instance, "bound_node_id": bound, "billing_notice": "直接给原机申请第二个公网 IPv4，额外 IP 可能按 Linode 价格收费；账号需要有额外 IPv4 配额。只有新 IP 通过连接验证后才释放旧 IP。"})
}
func (s *Server) ipChangeAPI(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account_id")
	id, err := strconv.Atoi(r.PathValue("id"))
	if account == "" || err != nil || id <= 0 {
		fail(w, 400, "请选择具体账号和实例")
		return
	}
	var in struct {
		Plan               string  `json:"plan"`
		ExpectedIP         string  `json:"expected_ip"`
		ConfirmID          int     `json:"confirm_instance_id"`
		ConfirmBilling     bool    `json:"confirm_billing"`
		ExpectedHourly     float64 `json:"expected_hourly"`
		NodeID             int     `json:"node_id"`
		CheckPort          int     `json:"check_port"`
		CheckChinaOriginal bool    `json:"check_china_original"`
		ChinaProbe         bool    `json:"china_probe"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in) != nil || !in.ConfirmBilling || in.ConfirmID != id || in.NodeID < 0 || in.CheckPort < 0 || in.CheckPort > 65535 {
		fail(w, 400, "请确认原机 ID、额外 IPv4 可能产生的费用和短暂关机")
		return
	}
	if in.CheckPort == 0 {
		in.CheckPort = 22
	}
	chinaProvider := ""
	if in.ChinaProbe {
		provider, providerErr := s.chinaProbeProvider()
		if providerErr != nil || !s.chinaProbeConfigured(provider) {
			fail(w, 409, "请先在“国内探测”设置中配置并选择探测方式")
			return
		}
		chinaProvider = provider
	}
	instance, err := s.ipInstance(r.Context(), account, id)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if publicIP(instance) != in.ExpectedIP {
		fail(w, 409, "原机 IP 已变化，请刷新后重试")
		return
	}
	if err := s.checkIPTarget(r.Context(), account, instance); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if in.NodeID == 0 && s.credentials != nil {
		if raw, ok := s.credentials.token("node-binding-" + account + "/" + strconv.Itoa(id)); ok {
			in.NodeID, _ = strconv.Atoi(raw)
		}
	}
	if in.NodeID > 0 {
		domain, err := s.wp2NodeDomain(r.Context(), env("WP2_BASE_URL", ""), env("WP2_API_TOKEN", ""), in.NodeID)
		if err != nil {
			fail(w, 409, "换 IP 前无法验证节点 DNS："+err.Error())
			return
		}
		config, err := s.dnsConfigFor(domain)
		if err != nil || config == nil {
			fail(w, 409, "绑定节点连接域名没有可用自动 DNS 配置，未申请新 IP")
			return
		}
		panel, _ := url.Parse(env("WP2_BASE_URL", ""))
		if domain == config.Zone || domain == strings.ToLower(env("PANEL_DOMAIN", "")) || (panel != nil && domain == panel.Hostname()) {
			fail(w, 409, "绑定节点使用受保护的根域名或面板域名，未申请新 IP")
			return
		}
	}
	if s.credentials != nil {
		s.credentials.mu.RLock()
		unfinished := ""
		for key, value := range s.credentials.accounts {
			if strings.HasPrefix(key, "ip-job-") {
				var prior IPChange
				if json.Unmarshal([]byte(value.Token), &prior) == nil && prior.Job.AccountID == account && prior.Original.ID == id && prior.HelperID > 0 && !prior.HelperCleaned {
					unfinished = prior.Job.ID
					break
				}
			}
		}
		s.credentials.mu.RUnlock()
		if unfinished != "" {
			fail(w, 409, "该原机有未处理的旧换 IP 任务，请先核对任务 "+unfinished)
			return
		}
	}
	jobID := "ip-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	op := &IPChange{Job: Job{ID: jobID, Kind: "ip_change", Status: "queued", InstanceID: id, TargetID: in.NodeID, AccountID: account, OldIP: in.ExpectedIP}, Original: instance, CheckPort: in.CheckPort, CheckChinaOriginal: in.CheckChinaOriginal, ChinaProbe: in.ChinaProbe, ChinaProvider: chinaProvider}
	op.UseProxy, _ = r.Context().Value(proxyContextKey{}).(bool)
	s.mu.Lock()
	for _, job := range s.jobs {
		if (job.Status == "queued" || job.Status == "running") && job.AccountID == account && job.InstanceID == id {
			s.mu.Unlock()
			fail(w, 409, "原机正在执行安装/换 IP，请等待任务完成")
			return
		}
	}
	s.jobs[jobID] = op.Job
	s.mu.Unlock()
	if err := s.saveIPChange(op); err != nil {
		s.mu.Lock()
		delete(s.jobs, jobID)
		s.mu.Unlock()
		fail(w, 500, "无法持久保存换 IP 任务，未申请新 IP")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(useProxyContext(context.Background(), op.UseProxy), 25*time.Minute)
		defer cancel()
		if err := s.runIPChange(ctx, op); err != nil && op.Job.Status == "running" {
			op.Job.Status = "failed"
			op.Job.Log += "\n换 IP 中断：" + err.Error()
			s.mu.Lock()
			s.jobs[jobID] = op.Job
			s.mu.Unlock()
		}
	}()
	send(w, 202, map[string]string{"job_id": jobID, "status": "queued"})
}
func (s *Server) ipChangeCleanupAPI(w http.ResponseWriter, r *http.Request) {
	op, err := s.loadIPChange(r.PathValue("job"))
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	var input struct {
		ConfirmID int `json:"confirm_instance_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil || input.ConfirmID != op.Original.ID {
		fail(w, 400, "请确认原机 ID")
		return
	}
	s.mu.RLock()
	job, active := s.jobs[op.Job.ID]
	s.mu.RUnlock()
	if active && (job.Status == "running" || job.Status == "queued") {
		fail(w, 409, "任务仍在运行，请等待")
		return
	}
	ctx := useProxyContext(r.Context(), op.UseProxy)
	if op.Job.Status == "queued" || op.Job.Status == "running" {
		op.Job.Status = "interrupted"
	}
	if op.HelperID == 0 {
		instances, err := s.instancesFor(ctx, op.Job.AccountID)
		if err != nil {
			fail(w, 502, "无法按标签查找临时实例")
			return
		}
		for _, instance := range instances {
			if instance.Label == op.HelperLabel {
				if op.HelperID != 0 {
					fail(w, 409, "临时实例标签不唯一，未删除")
					return
				}
				op.HelperID = instance.ID
			}
		}
		if op.HelperID == 0 {
			fail(w, 409, "尚未找到临时实例，请在 Linode 核对标签 "+op.HelperLabel+" 后再操作")
			return
		}
	}
	if err := s.cleanupIPHelper(ctx, op); err != nil {
		fail(w, 409, err.Error())
		return
	}
	send(w, 200, map[string]any{"deleted": true, "helper_id": op.HelperID})
}

func (s *Server) instanceChangingIP(account string, id int) bool {
	if account == "" {
		account = "legacy"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, job := range s.jobs {
		if job.Kind == "ip_change" && job.AccountID == account && (job.InstanceID == id || job.HelperID == id) && (job.Status == "queued" || job.Status == "running") {
			return true
		}
	}
	return false
}
func (s *Server) ipChangeListAPI(w http.ResponseWriter, r *http.Request) {
	jobs := []Job{}
	if s.credentials != nil {
		s.credentials.mu.RLock()
		for key, value := range s.credentials.accounts {
			if strings.HasPrefix(key, "ip-job-") {
				var op IPChange
				if json.Unmarshal([]byte(value.Token), &op) == nil {
					jobs = append(jobs, op.Job)
				}
			}
		}
		s.credentials.mu.RUnlock()
	}
	for i, job := range jobs {
		s.mu.RLock()
		live, ok := s.jobs[job.ID]
		s.mu.RUnlock()
		if ok {
			jobs[i] = live
		} else if job.Status == "queued" || job.Status == "running" {
			jobs[i].Status = "interrupted"
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID > jobs[j].ID })
	if len(jobs) > 20 {
		jobs = jobs[:20]
	}
	send(w, 200, map[string]any{"jobs": jobs})
}
