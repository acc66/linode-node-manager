package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Retry only a positively identified domestic TCP failure with a verified
// rollback. Unknown allocation results, probe outages and quota errors pause.
func (s *Server) ensureRefillIP(ctx context.Context, st *RefillState, account string, instance Instance, port int) (Instance, error) {
	checked, err := s.checkRefillChina(ctx, account, instance.ID, port)
	if err == nil {
		return checked, nil
	}
	if !errors.Is(err, errDomesticTCPUnreachable) || !st.Config.AutoIP {
		return checked, err
	}
	instance = checked
	for {
		if err := ctx.Err(); err != nil {
			return instance, err
		}
		st.Stage = "ip_retry"
		st.IPAttempts++
		if err := s.saveRefill(st, fmt.Sprintf("国内 IP 检查未通过，进行第 %d 轮原机换 IP；不设次数上限，可暂停", st.IPAttempts)); err != nil {
			return instance, err
		}
		if err := s.refillDelay(ctx, 15*time.Second); err != nil {
			return instance, err
		}
		var next Instance
		var op *IPChange
		if s.refillReplaceIP != nil {
			next, op, err = s.refillReplaceIP(ctx, account, instance, port, "aliyun", true)
		} else {
			next, op, err = s.replaceIPFromBoot(ctx, account, instance, port, "aliyun", true)
		}
		if err == nil {
			instance = next
			checked, err = s.checkRefillChina(ctx, account, instance.ID, port)
			if err == nil {
				return checked, nil
			}
			if !errors.Is(err, errDomesticTCPUnreachable) {
				return instance, err
			}
			instance = checked
			continue
		}
		if !errors.Is(err, errDomesticTCPUnreachable) {
			return instance, err
		}
		// Direct-IP replacement restores the old address after rejecting a candidate.
		// Read it back before requesting another candidate, otherwise pause.
		if op == nil || op.Job.IPChanged {
			return instance, errors.New("候选 IP 失败后原地址状态不明，暂停以核对分配结果")
		}
		current, readErr := s.ipInstance(ctx, account, instance.ID)
		if readErr != nil || current.Status != "running" || len(current.IPv4) != 1 || publicIP(current) != publicIP(instance) {
			return instance, errors.New("候选 IP 失败后未确认恢复为原机单一 IPv4，暂停以避免重复分配")
		}
		instance = current
		if err := s.saveRefill(st, "候选 IP 国内不可达，已核实恢复旧地址；稍后继续申请下一 IP"); err != nil {
			return instance, err
		}
	}
}
