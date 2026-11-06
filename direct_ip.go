package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

type interfaceIPv4Address struct {
	Address string `json:"address"`
	Primary bool   `json:"primary"`
}

type publicLinodeInterface struct {
	ID     int `json:"id"`
	Public *struct {
		IPv4 struct {
			Addresses []interfaceIPv4Address `json:"addresses"`
		} `json:"ipv4"`
	} `json:"public"`
}

func (s *Server) runIPChange(ctx context.Context, op *IPChange) error {
	return s.runDirectIPChange(ctx, op)
}

func (s *Server) getPublicLinodeInterface(ctx context.Context, account string, id int) (publicLinodeInterface, error) {
	var response struct {
		Data []publicLinodeInterface `json:"data"`
	}
	if err := s.ipJSON(ctx, account, "GET", fmt.Sprintf("/linode/instances/%d/interfaces", id), nil, &response); err != nil {
		return publicLinodeInterface{}, err
	}
	for _, iface := range response.Data {
		if iface.ID > 0 && iface.Public != nil {
			return iface, nil
		}
	}
	return publicLinodeInterface{}, errors.New("原机没有可更新的公网 Linode interface")
}

func (s *Server) updatePublicLinodeIPv4(ctx context.Context, account string, id int, iface publicLinodeInterface, addresses []interfaceIPv4Address) error {
	body := map[string]any{"public": map[string]any{"ipv4": map[string]any{"addresses": addresses}}}
	return s.ipJSON(ctx, account, "PUT", fmt.Sprintf("/linode/instances/%d/interfaces/%d", id, iface.ID), body, nil)
}

func containsIPv4(instance Instance, address string) bool {
	for _, ip := range instance.IPv4 {
		if ip == address {
			return true
		}
	}
	return false
}

func (s *Server) addDirectIPv4(ctx context.Context, op *IPChange, oldIP string) (newIP string, iface *publicLinodeInterface, err error) {
	if op.Original.InterfaceGeneration == "linode" {
		current, e := s.getPublicLinodeInterface(ctx, op.Job.AccountID, op.Original.ID)
		if e != nil {
			return "", nil, e
		}
		addresses := []interfaceIPv4Address{{Address: oldIP, Primary: true}, {Address: "auto", Primary: false}}
		if e = s.updatePublicLinodeIPv4(ctx, op.Job.AccountID, op.Original.ID, current, addresses); e != nil {
			return "", nil, fmt.Errorf("Linode interface 无法分配额外 IPv4（旧 IP 保留）：%w", e)
		}
		current, e = s.getPublicLinodeInterface(ctx, op.Job.AccountID, op.Original.ID)
		if e != nil {
			return "", nil, e
		}
		for _, address := range current.Public.IPv4.Addresses {
			if address.Address != oldIP && net.ParseIP(address.Address) != nil {
				return address.Address, &current, nil
			}
		}
		return "", &current, errors.New("interface 更新成功但未返回新 IPv4；旧 IP 保留，请核对 Linode")
	}
	var allocated struct {
		Address string `json:"address"`
		Linode  int    `json:"linode_id"`
		Public  bool   `json:"public"`
		Region  string `json:"region"`
	}
	body := map[string]any{"type": "ipv4", "public": true}
	if err := s.ipJSON(ctx, op.Job.AccountID, "POST", fmt.Sprintf("/linode/instances/%d/ips", op.Original.ID), body, &allocated); err != nil {
		return "", nil, fmt.Errorf("Linode 未允许给原机分配额外公网 IPv4，旧 IP 保留：%w", err)
	}
	if net.ParseIP(allocated.Address).To4() == nil || allocated.Address == oldIP || (allocated.Linode != 0 && allocated.Linode != op.Original.ID) || (allocated.Region != "" && allocated.Region != op.Original.Region) || (allocated.Public == false && allocated.Linode != 0) {
		return "", nil, errors.New("Linode 返回的新 IPv4 无效或归属不符；旧 IP 保留，请核对账号")
	}
	return allocated.Address, nil, nil
}

func (s *Server) releaseDirectIPv4(ctx context.Context, op *IPChange, oldIP, newIP string, iface *publicLinodeInterface) error {
	if iface != nil {
		return s.updatePublicLinodeIPv4(ctx, op.Job.AccountID, op.Original.ID, *iface, []interfaceIPv4Address{{Address: newIP, Primary: true}})
	}
	_, status, err := s.linodeFor(ctx, op.Job.AccountID, "DELETE", fmt.Sprintf("/linode/instances/%d/ips/%s", op.Original.ID, url.PathEscape(oldIP)), nil)
	if err != nil {
		return errors.New("释放旧 IPv4 的结果未知；新 IP 已分配，请核对原机地址")
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("释放旧 IPv4 HTTP %d；新 IP 保留，未删除原机", status)
	}
	return nil
}

func (s *Server) removeDirectIPv4(ctx context.Context, op *IPChange, address string, iface *publicLinodeInterface) error {
	if iface != nil {
		return s.updatePublicLinodeIPv4(ctx, op.Job.AccountID, op.Original.ID, *iface, []interfaceIPv4Address{{Address: op.Job.OldIP, Primary: true}})
	}
	_, status, err := s.linodeFor(ctx, op.Job.AccountID, "DELETE", fmt.Sprintf("/linode/instances/%d/ips/%s", op.Original.ID, url.PathEscape(address)), nil)
	if err != nil || status < 200 || status >= 300 {
		return errors.New("清理未使用的新 IPv4 未确认；原 IP 仍保留，请在 Linode 核对")
	}
	return nil
}

func (s *Server) bootAfterIPChange(ctx context.Context, account string, id int, running bool, expected string) (Instance, error) {
	if !running {
		return s.ipInstance(ctx, account, id)
	}
	if err := s.ipJSON(ctx, account, "POST", fmt.Sprintf("/linode/instances/%d/boot", id), map[string]any{}, nil); err != nil {
		return Instance{}, err
	}
	return s.waitIPInstance(ctx, account, id, func(instance Instance) bool {
		return instance.Status == "running" && containsIPv4(instance, expected)
	})
}

func (s *Server) verifyDirectIPv4(ctx context.Context, account string, instance Instance, ip string) error {
	probe := instance
	probe.IPv4 = []string{ip}
	if s.canTune(account, instance.ID) {
		if _, err := s.deploySSH(ctx, account, probe, "true"); err == nil {
			return nil
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip, "22"))
	if err != nil {
		return fmt.Errorf("新 IP 的 TCP/22 尚未连通：%w", err)
	}
	_ = conn.Close()
	return nil
}

func (s *Server) runDirectIPChange(ctx context.Context, op *IPChange) (runErr error) {
	op.Job.Status = "running"
	if err := s.saveIPChange(op); err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			op.Job.Status = "failed"
			s.ipJobLog(op, "直接更换 IP 未完成："+runErr.Error())
		} else {
			op.Job.Status = "success"
			s.ipJobLog(op, "原机直接更换 IPv4 完成；未创建临时 Linode。")
		}
		_ = s.saveIPChange(op)
	}()

	account := op.Job.AccountID
	original, err := s.ipInstance(ctx, account, op.Original.ID)
	if err != nil {
		return err
	}
	oldIP := publicIP(original)
	if oldIP == "" || oldIP != op.Job.OldIP || original.Region != op.Original.Region {
		return errors.New("原机 IP 或地区已变化，请刷新后重试")
	}
	if err := s.checkIPTarget(ctx, account, original); err != nil {
		return err
	}
	wasRunning := original.Status == "running"
	if wasRunning {
		s.ipJobLog(op, "停机期间给原机申请第二个 IPv4；确认新地址可用后才释放旧地址。")
		if err := s.ipJSON(ctx, account, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", original.ID), map[string]any{}, nil); err != nil {
			return err
		}
		original, err = s.waitIPInstance(ctx, account, original.ID, func(i Instance) bool { return i.Status == "offline" })
		if err != nil {
			return err
		}
	}

	newIP, iface, err := s.addDirectIPv4(ctx, op, oldIP)
	if err != nil {
		if wasRunning {
			_, _ = s.bootAfterIPChange(context.WithoutCancel(ctx), account, original.ID, true, oldIP)
		}
		return err
	}
	op.Job.NewIP = newIP
	if err := s.saveIPChange(op); err != nil {
		return errors.New("新 IP 已申请但任务保存失败；旧 IP 未释放，请在 Linode 核对")
	}
	s.ipJobLog(op, "已为原机分配新 IPv4="+newIP+"；旧 IP 暂时保留。")
	if err := moveBootstrapHostKey(oldIP, newIP); err != nil {
		s.ipJobLog(op, "新 IP 的 SSH 主机密钥缓存准备失败，将继续用 TCP/22 验证："+err.Error())
	}

	if iface != nil {
		addresses := []interfaceIPv4Address{{Address: oldIP, Primary: false}, {Address: newIP, Primary: true}}
		if err := s.updatePublicLinodeIPv4(ctx, account, original.ID, *iface, addresses); err != nil {
			_ = s.removeDirectIPv4(context.WithoutCancel(ctx), op, newIP, iface)
			if wasRunning {
				_, _ = s.bootAfterIPChange(context.WithoutCancel(ctx), account, original.ID, true, oldIP)
			}
			return fmt.Errorf("设置新 IPv4 为主地址失败，已尝试恢复旧地址：%w", err)
		}
		currentIface, getErr := s.getPublicLinodeInterface(ctx, account, original.ID)
		iface = &currentIface
		err = getErr
		if err != nil {
			return err
		}
	}

	if wasRunning {
		original, err = s.bootAfterIPChange(ctx, account, original.ID, true, newIP)
		if err != nil {
			return fmt.Errorf("新地址已配置，原机启动/分配确认失败；旧 IP 尚未释放：%w", err)
		}
		if err := s.verifyDirectIPv4(ctx, account, original, newIP); err != nil {
			s.ipJobLog(op, "新地址连接验证失败，尝试保留并恢复旧地址。")
			if stopErr := s.ipJSON(ctx, account, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", original.ID), map[string]any{}, nil); stopErr == nil {
				_, _ = s.waitIPInstance(ctx, account, original.ID, func(i Instance) bool { return i.Status == "offline" })
				_ = s.removeDirectIPv4(context.WithoutCancel(ctx), op, newIP, iface)
				if iface != nil {
					_ = s.updatePublicLinodeIPv4(context.WithoutCancel(ctx), account, original.ID, *iface, []interfaceIPv4Address{{Address: oldIP, Primary: true}})
				}
				_, _ = s.bootAfterIPChange(context.WithoutCancel(ctx), account, original.ID, true, oldIP)
			}
			return err
		}
	}

	if wasRunning {
		if err := s.ipJSON(ctx, account, "POST", fmt.Sprintf("/linode/instances/%d/shutdown", original.ID), map[string]any{}, nil); err != nil {
			return fmt.Errorf("新 IP 已验证，但释放旧 IP 前停机失败：%w", err)
		}
		original, err = s.waitIPInstance(ctx, account, original.ID, func(i Instance) bool { return i.Status == "offline" })
		if err != nil {
			return err
		}
	}
	if err := s.releaseDirectIPv4(ctx, op, oldIP, newIP, iface); err != nil {
		if wasRunning {
			_, _ = s.bootAfterIPChange(context.WithoutCancel(ctx), account, original.ID, true, newIP)
		}
		return err
	}
	original, err = s.ipInstance(ctx, account, original.ID)
	if err != nil {
		return fmt.Errorf("旧 IP 释放请求已成功但地址列表暂不可核实；新 IP=%s，请刷新 Linode 核对：%w", newIP, err)
	}
	if !containsIPv4(original, newIP) || containsIPv4(original, oldIP) {
		return errors.New("Linode 返回的 IPv4 列表与预期不符；未报告换 IP 成功，请核对原机网络")
	}
	op.SwapVerified = true
	op.Job.IPChanged = true
	if err := s.saveIPChange(op); err != nil {
		return errors.New("旧 IP 已释放但换 IP 结果保存失败；请刷新核对 Linode")
	}
	s.ipJobLog(op, "新 IPv4 已验证，旧 IPv4 已释放。")
	if wasRunning {
		original, err = s.bootAfterIPChange(ctx, account, original.ID, true, newIP)
		if err != nil {
			return fmt.Errorf("旧 IP 已释放，新 IP=%s；原机启动状态待核对：%w", newIP, err)
		}
	}
	if op.Job.TargetID > 0 {
		ready, log, dnsErr := s.prepareDeploymentDNS(ctx, env("WP2_BASE_URL", ""), env("WP2_API_TOKEN", ""), op.Job.TargetID, &original)
		s.ipJobLog(op, log)
		if dnsErr != nil {
			op.Job.DNSStatus = "failed"
			return fmt.Errorf("IP 已更换，但 DNS 更新失败：%w", dnsErr)
		}
		op.Job.DNSStatus = "skipped"
		if ready {
			op.Job.DNSStatus = "updated"
		}
	} else {
		op.Job.DNSStatus = "skipped"
		s.ipJobLog(op, "没有选择节点绑定，DNS 未自动更新。")
	}
	return nil
}
