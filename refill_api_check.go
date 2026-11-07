package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type RefillAPICheck struct {
	Account string    `json:"account_id"`
	Kind    string    `json:"kind"`
	Status  int       `json:"http_status,omitempty"`
	Message string    `json:"message"`
	At      time.Time `json:"checked_at"`
	Credit  *float64  `json:"credit_usd,omitempty"`
}

func validLinodeError(body []byte) bool {
	var value struct {
		Errors []struct {
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &value) != nil {
		return false
	}
	for _, issue := range value.Errors {
		if issue.Reason != "" {
			return true
		}
	}
	return false
}
func (s *Server) checkRefillAPI(ctx context.Context, account string) RefillAPICheck {
	check := RefillAPICheck{Account: account, Kind: "ok", Message: "账号认证与读取权限检查通过", At: time.Now().UTC()}
	for _, path := range []string{"/account", "/linode/instances?page_size=25"} {
		body, status, err := s.linodeFor(ctx, account, "GET", path, nil)
		check.Status = status
		if err != nil {
			check.Kind = "proxy_error"
			check.Message = "代理、出口检查或账号配置异常；未切换直连"
			if status == 0 || status == 502 {
				check.Kind = "unreachable"
				check.Message = "Linode API 连接失败或超时"
			}
			if ctx.Err() != nil {
				check.Kind = "cancelled"
				check.Message = "操作已停止"
			}
			return check
		}
		if status == 401 || status == 403 {
			if !validLinodeError(body) {
				check.Kind = "invalid_response"
				check.Message = "401/403 不是可核实的 Linode JSON 错误，不据此切号"
				return check
			}
			check.Kind = "auth_error"
			check.Message = "Linode API 确认 Token 无效或失效"
			if status == 403 {
				check.Kind = "permission_error"
				check.Message = "Linode API 确认当前操作权限不足"
			}
			return check
		}
		if status == 429 {
			check.Kind = "rate_limited"
			check.Message = "API 限流，等待后重试，不跳过账号"
			return check
		}
		if status >= 500 {
			check.Kind = "server_error"
			check.Message = "Linode API 服务错误，等待后重试，不跳过账号"
			return check
		}
		if status != http.StatusOK {
			check.Kind = "http_error"
			check.Message = fmt.Sprintf("API 返回 HTTP %d，暂停核对", status)
			return check
		}
		if path == "/account" {
			credit, parseErr := refillCredit(body, time.Now().UTC())
			if parseErr != nil {
				check.Kind = "invalid_response"
				check.Message = "账号账单响应无效，不能核实 API 健康状态"
				return check
			}
			check.Credit = &credit
		} else {
			var response struct {
				Data *[]json.RawMessage `json:"data"`
			}
			if json.Unmarshal(body, &response) != nil || response.Data == nil {
				check.Kind = "invalid_response"
				check.Message = "实例列表响应无效"
				return check
			}
		}
	}
	return check
}
func refillAuthFailure(check RefillAPICheck) bool {
	return check.Kind == "auth_error" || check.Kind == "permission_error"
}
func (s *Server) saveRefillCheck(st *RefillState, check RefillAPICheck) error {
	if st.APIChecks == nil {
		st.APIChecks = map[string]RefillAPICheck{}
	}
	st.APIChecks[check.Account] = check
	return s.saveRefill(st, "")
}
func (s *Server) refillDelay(ctx context.Context, delay time.Duration) error {
	if s.refillWait != nil {
		return s.refillWait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (s *Server) candidateRefillAPI(ctx context.Context, account string) (RefillAPICheck, error) {
	check := s.checkRefillAPI(ctx, account)
	for attempt := 1; check.Kind == "unreachable" && attempt < 3; attempt++ {
		if err := s.refillDelay(ctx, time.Duration(attempt)*3*time.Second); err != nil {
			return check, err
		}
		check = s.checkRefillAPI(ctx, account)
	}
	return check, nil
}
func (s *Server) currentRefillAPI(ctx context.Context, st *RefillState) (bool, error) {
	check := s.checkRefillAPI(ctx, st.CurrentAccount)
	if err := s.saveRefillCheck(st, check); err != nil {
		return false, err
	}
	if check.Kind == "cancelled" {
		return false, context.Canceled
	}
	if check.Kind == "ok" {
		st.APIFailures = 0
		st.LastAPIFailure = time.Time{}
		st.CurrentCredit = check.Credit
		low := check.Credit != nil && *check.Credit <= st.Config.CreditFloor
		if low && !st.CreditAlerted {
			st.CreditAlerted = true
			message := fmt.Sprintf("账号 %s 剩余估算额度 $%.2f，已到提醒阈值；API 正常，不切号", st.CurrentAccount, *check.Credit)
			if err := s.saveRefill(st, message); err != nil {
				return false, err
			}
			go s.telegram(message)
		}
		if !low {
			st.CreditAlerted = false
		}
		st.Stage = "ready"
		return false, s.saveRefill(st, "当前账号 API 正常，继续使用；额度仅提醒，不检查旧机 TCP 或流量")
	}
	if refillAuthFailure(check) {
		st.APIFailures = 0
		return true, s.saveRefill(st, check.Message+"；开始检测后续候选账号")
	}
	if check.Kind == "unreachable" {
		// Persist spaced samples so refreshes and restarts cannot manufacture a streak.
		now := time.Now().UTC()
		if st.LastAPIFailure.IsZero() || now.Sub(st.LastAPIFailure) >= time.Minute {
			st.APIFailures++
			st.LastAPIFailure = now
		}
		if st.APIFailures >= 3 {
			return true, s.saveRefill(st, "当前账号 API 已连续三轮不可达，先检测候选账号，再决定是否建机")
		}
		st.Stage = "api_wait"
		return false, s.saveRefill(st, fmt.Sprintf("API 连接失败 %d/3，等待下一轮；未切号", st.APIFailures))
	}
	st.APIFailures = 0
	st.LastAPIFailure = time.Time{}
	st.Stage = "api_wait"
	if check.Kind == "rate_limited" || check.Kind == "server_error" {
		return false, s.saveRefill(st, check.Message)
	}
	return false, errors.New(check.Message)
}

func (s *Server) accountAPICheckAPI(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("id")
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "账号不存在或未配置")
		return
	}
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		taskID = defaultRefillTask
	}
	rt := s.refillRuntime(taskID)
	if !rt.mu.TryLock() {
		fail(w, 409, "运维任务正在运行，请等待后测试")
		return
	}
	defer rt.mu.Unlock()
	st, err := s.loadRefillTask(taskID)
	if err != nil {
		fail(w, 503, err.Error())
		return
	}
	check := s.checkRefillAPI(refillContext(r.Context()), account)
	if err := s.saveRefillCheck(&st, check); err != nil {
		fail(w, 500, "API 检查记录保存失败")
		return
	}
	send(w, 200, check)
}
