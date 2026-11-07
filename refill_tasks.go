package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultRefillTask = "default"

var errRefillOwned = errors.New("补机资源已被其他任务占用")
var errRefillYield = errors.New("补机任务等待下一轮重试")

type refillTaskRuntime struct {
	mu             sync.Mutex
	cancel         context.CancelFunc
	pauseRequested bool
	starting       bool
}

func validRefillTaskID(id string) bool {
	if id == defaultRefillTask {
		return true
	}
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
func refillTaskKey(id string) string {
	if id == defaultRefillTask {
		return "refill-state/0"
	}
	return "refill-task-" + id + "/0"
}
func storedRefillTask(key string) (string, bool) {
	if key == "refill-state/0" {
		return defaultRefillTask, true
	}
	if strings.HasPrefix(key, "refill-task-") && strings.HasSuffix(key, "/0") {
		id := strings.TrimSuffix(strings.TrimPrefix(key, "refill-task-"), "/0")
		return id, validRefillTaskID(id)
	}
	return "", false
}
func normalizeRefillTask(st *RefillState, id string) {
	st.TaskID = id
	if st.Name == "" {
		st.Name = "默认任务"
		if id != defaultRefillTask {
			st.Name = "补机任务"
		}
	}
	if st.Config.Trigger != "api" {
		st.Config.CreditFloor = 0
	}
	st.Config.Trigger = "api"
	st.Config.ReserveGB = 0
	st.Config.StopPercent = 0
	st.Config.TransferPercent = 0
}
func (s *Server) loadRefillTask(id string) (RefillState, error) {
	st := RefillState{TaskID: id, Name: "默认任务", Config: defaultRefillConfig(), Stage: "idle", History: []RefillEvent{}}
	if !validRefillTaskID(id) {
		return st, os.ErrNotExist
	}
	if s.credentials == nil {
		return st, errors.New("请配置 ACCOUNT_ENCRYPTION_KEY 启用加密存储")
	}
	raw, ok := s.credentials.token(refillTaskKey(id))
	if !ok {
		if id == defaultRefillTask {
			return st, nil
		}
		return st, os.ErrNotExist
	}
	st.Config.Trigger = ""
	if json.Unmarshal([]byte(raw), &st) != nil {
		return st, errors.New("补机任务记录损坏，已停止操作")
	}
	normalizeRefillTask(&st, id)
	return st, nil
}
func (s *Server) listRefillTasks() ([]RefillState, error) {
	if s.credentials == nil {
		return nil, errors.New("请先配置加密存储")
	}
	s.credentials.mu.RLock()
	defer s.credentials.mu.RUnlock()
	out := []RefillState{}
	hasDefault := false
	for key, record := range s.credentials.accounts {
		id, ok := storedRefillTask(key)
		if !ok {
			continue
		}
		st := RefillState{Config: defaultRefillConfig()}
		st.Config.Trigger = ""
		if json.Unmarshal([]byte(record.Token), &st) != nil {
			return nil, errors.New("补机任务记录损坏，请核对加密存储")
		}
		normalizeRefillTask(&st, id)
		out = append(out, st)
		hasDefault = hasDefault || id == defaultRefillTask
	}
	if !hasDefault {
		out = append(out, RefillState{TaskID: defaultRefillTask, Name: "默认任务", Config: defaultRefillConfig(), Stage: "idle", History: []RefillEvent{}})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TaskID == out[j].TaskID {
			return false
		}
		if out[i].TaskID == defaultRefillTask {
			return true
		}
		if out[j].TaskID == defaultRefillTask {
			return false
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}
func refillClaimedAccounts(st RefillState) map[string]bool {
	claims := map[string]bool{}
	if st.CurrentID > 0 && st.CurrentAccount != "" {
		claims[st.CurrentAccount] = true
	}
	if st.Pending != nil && st.Pending.Account != "" {
		claims[st.Pending.Account] = true
	}
	// Retired accounts are not automatically recycled while their resources may remain.
	for _, old := range st.Retired {
		if old.ID > 0 && old.Account != "" {
			claims[old.Account] = true
		}
	}
	return claims
}
func checkRefillOwnersLocked(store *accountStore, st RefillState) error {
	claims := refillClaimedAccounts(st)
	for key, record := range store.accounts {
		id, ok := storedRefillTask(key)
		if !ok || id == st.TaskID {
			continue
		}
		var other RefillState
		if json.Unmarshal([]byte(record.Token), &other) != nil {
			return errors.New("其他任务记录损坏，无法核实资源占用")
		}
		for account := range refillClaimedAccounts(other) {
			if claims[account] {
				return fmt.Errorf("%w：账号 %s（任务 %s）", errRefillOwned, account, id)
			}
		}
		if st.Config.Domain != "" && st.Config.Domain == other.Config.Domain {
			return fmt.Errorf("%w：接替域名（任务 %s）", errRefillOwned, id)
		}
	}
	return nil
}
func (s *Server) accountAvailableForTask(taskID, account string) (bool, error) {
	if taskID == "" {
		taskID = defaultRefillTask
	}
	tasks, err := s.listRefillTasks()
	if err != nil {
		return false, err
	}
	for _, task := range tasks {
		if task.TaskID != taskID && refillClaimedAccounts(task)[account] {
			return false, nil
		}
	}
	return true, nil
}
func (s *Server) refillRuntime(id string) *refillTaskRuntime {
	s.refillTasksMu.Lock()
	defer s.refillTasksMu.Unlock()
	if s.refillTasks == nil {
		s.refillTasks = map[string]*refillTaskRuntime{}
	}
	if s.refillMonitorSlots == nil {
		s.refillMonitorSlots = make(chan struct{}, 6)
	}
	if s.refillTasks[id] == nil {
		s.refillTasks[id] = &refillTaskRuntime{}
	}
	return s.refillTasks[id]
}
func (s *Server) taskContext(parent context.Context, rt *refillTaskRuntime) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	s.refillTasksMu.Lock()
	rt.cancel = cancel
	rt.starting = false
	pause := rt.pauseRequested
	rt.pauseRequested = false
	s.refillTasksMu.Unlock()
	if pause {
		cancel()
	}
	return ctx, func() {
		cancel()
		s.refillTasksMu.Lock()
		rt.cancel = nil
		rt.pauseRequested = false
		rt.starting = false
		s.refillTasksMu.Unlock()
	}
}
func (s *Server) failRefillTask(st *RefillState, err error) {
	st.Config.Enabled = false
	st.QueuedAction = ""
	st.NextRunAt = time.Time{}
	st.Stage = "failed"
	if errors.Is(err, context.Canceled) {
		st.Stage = "paused"
	}
	if saveErr := s.saveRefill(st, err.Error()); saveErr != nil {
		log.Printf("refill task %s: state save failed", st.TaskID)
		return
	}
	go s.telegram("补机任务 [" + st.Name + "] 已暂停：" + err.Error())
}
func (s *Server) monitorRefillTask(parent context.Context, id string, rt *refillTaskRuntime) {
	defer rt.mu.Unlock()
	defer func() { <-s.refillMonitorSlots }()
	ctx, done := s.taskContext(parent, rt)
	defer done()
	st, err := s.loadRefillTask(id)
	if err != nil {
		return
	}
	if ctx.Err() != nil {
		s.failRefillTask(&st, ctx.Err())
		return
	}
	if !st.Config.Enabled || st.QueuedAction != "" || st.Pending != nil {
		return
	}
	st.LastCheck = time.Now().UTC()
	if err = s.validateRefill(&st.Config); err != nil {
		s.failRefillTask(&st, err)
		return
	}
	need := st.CurrentID == 0
	if !need {
		need, err = s.currentRefillAPI(refillContext(ctx), &st)
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		s.failRefillTask(&st, err)
		return
	}
	if need {
		st.QueuedAction = "run"
		st.QueuedAt = time.Now().UTC()
		st.Stage = "queued"
		err = s.saveRefill(&st, "已进入付费操作队列；其他任务继续独立监控")
	}
	if err != nil {
		s.failRefillTask(&st, err)
	}
}
func (s *Server) executeRefillTask(parent context.Context, id string, rt *refillTaskRuntime) {
	defer s.refillMu.Unlock()
	defer rt.mu.Unlock()
	ctx, done := s.taskContext(parent, rt)
	defer done()
	st, err := s.loadRefillTask(id)
	if err != nil {
		return
	}
	if ctx.Err() != nil {
		s.failRefillTask(&st, ctx.Err())
		return
	}
	action := st.QueuedAction
	if action == "" {
		return
	}
	st.QueuedAction = ""
	st.NextRunAt = time.Time{}
	st.Operation = action
	if err = s.saveRefill(&st, "开始执行任务操作："+action); err != nil {
		s.failRefillTask(&st, err)
		return
	}
	switch action {
	case "run", "resume":
		err = s.runRefill(ctx, &st, action == "resume")
	case "continue":
		if st.Pending == nil {
			err = errors.New("没有可继续的待建实例")
		} else {
			err = s.finishRefill(refillContext(ctx), &st)
		}
	default:
		err = s.refillInstanceAction(refillContext(ctx), &st, action)
	}
	if errors.Is(err, errRefillYield) {
		return
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		s.failRefillTask(&st, err)
		return
	}
	st.Operation = ""
	_ = s.saveRefill(&st, "")
}
func (s *Server) recoverRefillTasks() {
	tasks, err := s.listRefillTasks()
	if err != nil {
		return
	}
	for _, st := range tasks {
		switch st.Stage {
		case "idle", "draft", "ready", "failed", "exhausted", "api_wait", "paused", "account_wait", "queued", "interrupted":
			continue
		}
		st.Config.Enabled = false
		st.QueuedAction = ""
		st.NextRunAt = time.Time{}
		st.Stage = "interrupted"
		_ = s.saveRefill(&st, "进程重启时发现未完成操作，已暂停；请按任务 ID 核对后恢复")
	}
}
func (s *Server) refillScheduler(ctx context.Context) {
	s.recoverRefillTasks()
	if ctx.Err() != nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refillTaskTick(ctx)
		}
	}
}
func (s *Server) refillTaskTick(ctx context.Context) {
	tasks, err := s.listRefillTasks()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, st := range tasks {
		if !st.Config.Enabled || st.Pending != nil || st.QueuedAction != "" || now.Sub(st.LastCheck) < time.Duration(st.Config.IntervalMinutes)*time.Minute {
			continue
		}
		rt := s.refillRuntime(st.TaskID)
		if !rt.mu.TryLock() {
			continue
		}
		select {
		case s.refillMonitorSlots <- struct{}{}:
			s.refillTasksMu.Lock()
			rt.starting = true
			s.refillTasksMu.Unlock()
			go s.monitorRefillTask(ctx, st.TaskID, rt)
		default:
			rt.mu.Unlock()
		}
	}
	s.mu.RLock()
	legacyBusy := false
	for _, job := range s.jobs {
		if job.Status == "queued" || job.Status == "running" {
			legacyBusy = true
			break
		}
	}
	s.mu.RUnlock()
	if legacyBusy {
		return
	}
	sort.SliceStable(tasks, func(i, j int) bool { return tasks[i].QueuedAt.Before(tasks[j].QueuedAt) })
	for _, st := range tasks {
		if st.QueuedAction == "" || st.NextRunAt.After(now) {
			continue
		}
		rt := s.refillRuntime(st.TaskID)
		if !rt.mu.TryLock() {
			continue
		}
		if !s.refillMu.TryLock() {
			rt.mu.Unlock()
			return
		}
		// Legacy handlers hold a shared operation lock while publishing their job.
		// Recheck after taking the exclusive lock to close that publication race.
		s.mu.RLock()
		published := false
		for _, job := range s.jobs {
			if job.Status == "queued" || job.Status == "running" {
				published = true
				break
			}
		}
		s.mu.RUnlock()
		if published {
			s.refillMu.Unlock()
			rt.mu.Unlock()
			return
		}
		s.refillTasksMu.Lock()
		rt.starting = true
		s.refillTasksMu.Unlock()
		go s.executeRefillTask(ctx, st.TaskID, rt)
		return
	}
}
func taskStatusURL(id string) string { return "/api/refill/tasks/" + id }
func (s *Server) sendRefillTask(w http.ResponseWriter, st RefillState) {
	if st.Pending != nil {
		copyPending := *st.Pending
		copyPending.Password = ""
		st.Pending = &copyPending
	}
	rt := s.refillRuntime(st.TaskID)
	busy := !rt.mu.TryLock()
	if !busy {
		rt.mu.Unlock()
	}
	send(w, 200, map[string]any{"task_id": st.TaskID, "state": st, "busy": busy || st.QueuedAction != "", "status_url": taskStatusURL(st.TaskID)})
}
func refillTaskFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		fail(w, 404, "补机任务不存在")
		return
	}
	if errors.Is(err, errRefillOwned) {
		fail(w, 409, err.Error())
		return
	}
	fail(w, 500, err.Error())
}
func (s *Server) refillTasksAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tasks, err := s.listRefillTasks()
		if err != nil {
			refillTaskFailure(w, err)
			return
		}
		out := []map[string]any{}
		for _, st := range tasks {
			rt := s.refillRuntime(st.TaskID)
			busy := !rt.mu.TryLock()
			if !busy {
				rt.mu.Unlock()
			}
			out = append(out, map[string]any{"task_id": st.TaskID, "name": st.Name, "stage": st.Stage, "enabled": st.Config.Enabled, "current_account": st.CurrentAccount, "current_instance": st.CurrentID, "current_ip": st.CurrentIP, "ip_attempts": st.IPAttempts, "queued_action": st.QueuedAction, "next_run_at": st.NextRunAt, "busy": busy || st.QueuedAction != "", "created_at": st.CreatedAt, "updated_at": st.UpdatedAt, "status_url": taskStatusURL(st.TaskID)})
		}
		send(w, 200, map[string]any{"tasks": out})
		return
	}
	var in struct {
		Name    string        `json:"name"`
		Config  *RefillConfig `json:"config"`
		Billing bool          `json:"confirm_billing"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "任务格式无效")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len([]rune(in.Name)) < 1 || len([]rune(in.Name)) > 80 {
		fail(w, 400, "任务名称需要 1-80 个字符")
		return
	}
	tasks, err := s.listRefillTasks()
	if err != nil {
		refillTaskFailure(w, err)
		return
	}
	if len(tasks) >= 100 {
		fail(w, 400, "最多保存 100 个补机任务")
		return
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		fail(w, 500, "任务 ID 生成失败")
		return
	}
	st := RefillState{TaskID: hex.EncodeToString(random), Name: in.Name, Config: defaultRefillConfig(), Stage: "draft", History: []RefillEvent{}}
	if in.Config != nil {
		st.Config = *in.Config
		if err = s.validateRefill(&st.Config); err != nil {
			fail(w, 400, err.Error())
			return
		}
		st.Stage = "idle"
	}
	if st.Config.Enabled && !in.Billing {
		fail(w, 400, "启用自动付费操作前需要确认费用")
		return
	}
	if err = s.saveRefill(&st, "任务已新建，可凭任务 ID 查询；未创建云服务器"); err != nil {
		refillTaskFailure(w, err)
		return
	}
	send(w, 201, map[string]any{"task_id": st.TaskID, "status": st.Stage, "status_url": taskStatusURL(st.TaskID), "name": st.Name})
}
func (s *Server) refillTaskAPI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("task")
	st, err := s.loadRefillTask(id)
	if err != nil {
		refillTaskFailure(w, err)
		return
	}
	if r.Method == "GET" {
		s.sendRefillTask(w, st)
		return
	}
	rt := s.refillRuntime(id)
	if !rt.mu.TryLock() {
		fail(w, 409, "该任务正在运行，请先安全暂停")
		return
	}
	defer rt.mu.Unlock()
	st, err = s.loadRefillTask(id)
	if err != nil {
		refillTaskFailure(w, err)
		return
	}
	if r.Method == "DELETE" {
		if id == defaultRefillTask || st.CurrentID > 0 || st.Pending != nil || len(st.Retired) > 0 || st.QueuedAction != "" || st.Config.Enabled {
			fail(w, 409, "仅可删除已停用且从未占用云资源的任务；默认任务不能删除")
			return
		}
		if err = s.credentials.remove(refillTaskKey(id)); err != nil {
			refillTaskFailure(w, err)
			return
		}
		send(w, 200, map[string]any{"deleted": true, "task_id": id})
		return
	}
	if st.QueuedAction != "" || st.Pending != nil {
		fail(w, 409, "该任务排队中或存在未完成实例，请先暂停或核对恢复")
		return
	}
	var in struct {
		Name     *string       `json:"name"`
		Config   *RefillConfig `json:"config"`
		Account  *string       `json:"current_account"`
		Instance *int          `json:"current_instance"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "任务配置格式无效")
		return
	}
	if in.Name != nil {
		st.Name = strings.TrimSpace(*in.Name)
		if len([]rune(st.Name)) < 1 || len([]rune(st.Name)) > 80 {
			fail(w, 400, "任务名称需要 1-80 个字符")
			return
		}
	}
	if in.Config != nil {
		if err = s.validateRefill(in.Config); err != nil {
			fail(w, 400, err.Error())
			return
		}
		st.Config = *in.Config
	}
	if in.Account != nil {
		st.CurrentAccount = *in.Account
	}
	if in.Instance != nil {
		st.CurrentID = *in.Instance
	}
	if st.CurrentID < 0 {
		fail(w, 400, "实例 ID 无效")
		return
	}
	if in.Instance != nil || in.Account != nil {
		if st.CurrentID > 0 {
			match := false
			for _, account := range st.Config.Accounts {
				match = match || account == st.CurrentAccount
			}
			if !match {
				fail(w, 400, "当前账号不在任务队列中")
				return
			}
			instance, readErr := s.ipInstance(refillContext(r.Context()), st.CurrentAccount, st.CurrentID)
			if readErr != nil {
				fail(w, 400, "无法核实当前实例")
				return
			}
			st.CurrentIP = publicIP(instance)
		} else {
			st.CurrentAccount = ""
			st.CurrentIP = ""
		}
	}
	st.CurrentCredit = nil
	st.APIFailures = 0
	st.LastAPIFailure = time.Time{}
	st.CreditAlerted = false
	st.Stage = "idle"
	st.Cursor = 0
	for i, account := range st.Config.Accounts {
		if st.CurrentID > 0 && account == st.CurrentAccount {
			st.Cursor = i + 1
		}
	}
	if err = s.saveRefill(&st, "任务配置已加密保存"); err != nil {
		refillTaskFailure(w, err)
		return
	}
	send(w, 200, map[string]any{"saved": true, "task_id": id, "status_url": taskStatusURL(id)})
}
func (s *Server) pauseRefillTask(w http.ResponseWriter, id string, rt *refillTaskRuntime) {
	if !rt.mu.TryLock() {
		s.refillTasksMu.Lock()
		cancel := rt.cancel
		if cancel == nil && !rt.starting {
			s.refillTasksMu.Unlock()
			fail(w, 409, "该任务设置正在保存或检查，请稍后再暂停")
			return
		}
		if cancel == nil {
			rt.pauseRequested = true
		}
		s.refillTasksMu.Unlock()
		if cancel != nil {
			cancel()
		}
		send(w, 202, map[string]any{"task_id": id, "status": "stopping", "status_url": taskStatusURL(id)})
		return
	}
	defer rt.mu.Unlock()
	st, err := s.loadRefillTask(id)
	if err != nil {
		refillTaskFailure(w, err)
		return
	}
	st.Config.Enabled = false
	st.QueuedAction = ""
	st.NextRunAt = time.Time{}
	st.Stage = "paused"
	if err = s.saveRefill(&st, "此任务已暂停，其他任务不受影响"); err != nil {
		refillTaskFailure(w, err)
		return
	}
	send(w, 200, map[string]any{"task_id": id, "paused": true})
}
func (s *Server) refillTaskActionAPI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("task")
	if _, err := s.loadRefillTask(id); err != nil {
		refillTaskFailure(w, err)
		return
	}
	rt := s.refillRuntime(id)
	action := r.PathValue("action")
	if action == "pause" {
		s.pauseRefillTask(w, id, rt)
		return
	}
	if !rt.mu.TryLock() {
		fail(w, 409, "该任务正在运行")
		return
	}
	defer rt.mu.Unlock()
	st, err := s.loadRefillTask(id)
	if err != nil {
		refillTaskFailure(w, err)
		return
	}
	if st.QueuedAction != "" {
		fail(w, 409, "该任务已经排队，不能重复提交")
		return
	}
	var in struct {
		Billing bool `json:"confirm_billing"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in) != nil {
		fail(w, 400, "请求格式无效")
		return
	}
	if action != "run" && action != "resume" && action != "probe" && action != "boot" && action != "change-ip" {
		fail(w, 404, "未知任务操作")
		return
	}
	if action != "probe" && !in.Billing {
		fail(w, 400, "请确认实例与 IPv4 费用")
		return
	}
	if st.Pending != nil && action != "resume" {
		fail(w, 409, "存在未完成实例，只能核对后恢复")
		return
	}
	if action == "resume" && st.Pending == nil {
		fail(w, 409, "没有可恢复的未完成实例")
		return
	}
	if action == "run" {
		if err = s.validateRefill(&st.Config); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	if action == "probe" || action == "boot" || action == "change-ip" {
		if st.CurrentID <= 0 {
			fail(w, 400, "请先绑定当前实例")
			return
		}
		if !s.chinaProbeConfigured("aliyun") {
			fail(w, 409, "请先配置阿里云探测机")
			return
		}
	}
	st.QueuedAction = action
	st.QueuedAt = time.Now().UTC()
	st.NextRunAt = time.Time{}
	st.Stage = "queued"
	if err = s.saveRefill(&st, "操作已排队："+action); err != nil {
		refillTaskFailure(w, err)
		return
	}
	send(w, 202, map[string]any{"task_id": id, "status": "queued", "status_url": taskStatusURL(id)})
}
