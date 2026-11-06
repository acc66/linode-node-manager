package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const systemTuningScript = `set -eu
export LC_ALL=C
if ! command -v sysctl >/dev/null || ! command -v modprobe >/dev/null; then
 if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq procps kmod; fi
fi
mkdir -p /etc/sysctl.d /etc/security/limits.d
cat > /etc/security/limits.d/90-linode-manager.conf <<'LNM_LIMITS'
root soft nofile 65535
root hard nofile 65535
* soft nofile 65535
* hard nofile 65535
LNM_LIMITS
chmod 644 /etc/security/limits.d/90-linode-manager.conf
modprobe tcp_bbr 2>/dev/null || true
available=$(sysctl -n net.ipv4.tcp_available_congestion_control)
case " $available " in
 *" bbr "*)
  cat > /etc/sysctl.d/99-zz-linode-manager-bbr.conf <<'LNM_BBR'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
LNM_BBR
  sysctl -p /etc/sysctl.d/99-zz-linode-manager-bbr.conf
  echo "BBR_ENABLED: $(sysctl -n net.ipv4.tcp_congestion_control)"
  ;;
 *) echo 'BBR_UNSUPPORTED: 当前内核未提供 bbr，未安装第三方内核。' ;;
esac
echo 'NOFILE_CONFIGURED: root/* 登录会话 soft/hard 65535，配置已持久保存。'
`

func bootInitializationScript(openAllPorts bool) string {
	script := systemTuningScript
	if openAllPorts {
		script += `
if command -v ufw >/dev/null 2>&1; then
 status=$(ufw status 2>/dev/null || true)
 case "$status" in
  *"Status: active"*)
   rules=$(ufw status numbered 2>/dev/null || true)
   printf '%s\n' "$rules" | grep -Eq 'ALLOW IN +Anywhere' || ufw insert 1 allow in from any to any
   rules=$(ufw status numbered 2>/dev/null || true)
   printf '%s\n' "$rules" | grep -Eq 'ALLOW OUT +Anywhere' || ufw insert 1 allow out from any to any
   echo 'UFW_ALL_PORTS_ENABLED: active firewall allows all inbound and outbound traffic.'
   ;;
  *) echo 'UFW_INACTIVE: no local firewall rules required.' ;;
 esac
else
 echo 'UFW_NOT_INSTALLED: Linode cloud firewall configuration remains in effect.'
fi
`
	}
	return script
}

func (s *Server) canTune(account string, id int) bool {
	if s.passwordSaved(account, id) {
		return true
	}
	_, keyErr := os.Stat(env("SSH_PRIVATE_KEY_PATH", "/run/secrets/linode_ssh_key"))
	_, knownErr := os.Stat(env("SSH_KNOWN_HOSTS_PATH", "/run/secrets/known_hosts"))
	return keyErr == nil && knownErr == nil
}
func (s *Server) tuneNode(ctx context.Context, account string, instance Instance, openAllPorts bool) (string, error) {
	var output string
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		output, err = s.deploySSH(ctx, account, instance, bootInitializationScript(openAllPorts))
		if err == nil {
			return output, nil
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return output, ctx.Err()
		case <-timer.C:
		}
	}
	return output, err
}
func (s *Server) queueBootTuning(account string, id int, useProxy bool) string {
	if account == "" {
		account = "legacy"
	}
	return s.queueBootTuningWithCheck(account, id, useProxy, false)
}

func (s *Server) queueBootTuningWithCheck(account string, id int, useProxy, aliyunCheck bool) string {
	if s.skipBootTuning {
		return ""
	}
	canTune := s.canTune(account, id)
	bootSettings, settingsErr := s.chinaBootSettings()
	provider, providerErr := s.chinaProbeProvider()
	if aliyunCheck {
		bootSettings.Enabled = true
		bootSettings.Port = 22
		bootSettings.AutoReplace = false
		provider = "aliyun"
		providerErr = nil
	}
	checkChina := settingsErr == nil && providerErr == nil && bootSettings.Enabled && s.chinaProbeConfigured(provider)
	if !canTune && !checkChina {
		return ""
	}
	jobID := "boot-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	job := Job{ID: jobID, Kind: "boot_tuning", AccountID: account, InstanceID: id, Status: "queued"}
	if canTune {
		job.Log += "等待实例运行，配置 BBR 与 nofile…\n"
	}
	if checkChina {
		job.Log += fmt.Sprintf("开机后将使用 %s 检查 TCP/%d。\n", provider, bootSettings.Port)
	} else if settingsErr != nil {
		job.Log += "开机 IP 检测设置无效：" + settingsErr.Error() + "\n"
	} else if bootSettings.Enabled && (providerErr != nil || !s.chinaProbeConfigured(provider)) {
		job.Log += "开机 IP 检测已启用，但所选国内探测方式未配置；本次只执行可用的开机优化。\n"
	}
	s.mu.Lock()
	s.jobs[jobID] = job
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(useProxyContext(context.Background(), useProxy), 35*time.Minute)
		defer cancel()
		instance, err := s.waitIPInstance(ctx, account, id, func(i Instance) bool { return i.Status == "running" && publicIP(i) != "" })
		if err != nil {
			job.Status = "failed"
			job.Log += "开机等待实例运行失败：" + err.Error() + "\n"
		} else if job.Status == "queued" {
			job.Status = "running"
		}
		if err == nil && checkChina {
			job.Log += fmt.Sprintf("等待实例 TCP/%d 开始监听，未监听时不会误判为 IP 被墙。\n", bootSettings.Port)
			s.publishBootJob(job)
			probeInstance, portErr := s.waitBootProbePort(ctx, account, id, bootSettings.Port)
			if portErr != nil {
				job.Status = "partial"
				job.Log += "开机 IP 检测跳过：" + portErr.Error() + "\n"
			} else {
				instance = probeInstance
				job.Log += fmt.Sprintf("开始 %s 探测 %s TCP/%d…\n", provider, publicIP(instance), bootSettings.Port)
				s.publishBootJob(job)
				output, probeErr := s.checkChinaTCP(ctx, provider, publicIP(instance), bootSettings.Port)
				if probeErr == nil {
					job.Log += "国内 IP/TCP 检测通过：" + output + "\n"
				} else if errors.Is(probeErr, errDomesticTCPUnreachable) {
					job.Log += "国内探测无法连接当前 IP，但面板本机端口可达：" + output + "\n"
					if !bootSettings.AutoReplace {
						job.Status = "partial"
						job.Log += "自动换 IP 已关闭，保留当前 IP。\n"
					} else {
						job.Log += "开始自动申请并验证候选 IP；候选地址不通过国内 TCP 检查时会保留旧 IP。\n"
						s.publishBootJob(job)
						replacement, op, replaceErr := s.replaceIPFromBoot(ctx, account, instance, bootSettings.Port, provider, useProxy)
						if replacement.ID == instance.ID && publicIP(replacement) != "" {
							instance = replacement
						}
						if replaceErr != nil {
							job.Status = "failed"
							if op != nil && op.Job.IPChanged {
								job.Status = "partial"
							}
							job.Log += "开机自动换 IP 失败：" + replaceErr.Error() + "\n"
						}
						if op != nil {
							job.Log += op.Job.Log
							if op.Job.DNSStatus == "failed" {
								job.Status = "partial"
							}
						}
						if replaceErr == nil {
							job.Log += "开机自动换 IP 完成，新 IP=" + publicIP(instance) + "\n"
						}
					}
				} else {
					job.Status = "partial"
					job.Log += "国内 IP 探测未能判定，保留当前 IP：" + probeErr.Error() + "\n"
				}
			}
		}
		if err == nil && canTune {
			output, tuneErr := s.tuneNode(ctx, account, instance, s.openPortsSaved(account, id))
			job.Log += output
			if tuneErr != nil {
				if job.Status != "failed" {
					job.Status = "partial"
				}
				job.Log += "\n开机优化失败，请核对 SSH：" + tuneErr.Error() + "\n"
			} else if strings.Contains(output, "BBR_UNSUPPORTED") && job.Status == "running" {
				job.Status = "partial"
			}
		}
		if job.Status == "running" {
			job.Status = "success"
			if bootSettings.Enabled && !checkChina {
				job.Status = "partial"
			}
		}
		s.mu.Lock()
		s.jobs[jobID] = job
		s.mu.Unlock()
	}()
	return jobID
}

func (s *Server) publishBootJob(job Job) {
	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()
}

func (s *Server) waitBootProbePort(ctx context.Context, account string, id, port int) (Instance, error) {
	for attempt := 0; attempt < 30; attempt++ {
		instance, err := s.ipInstance(ctx, account, id)
		if err == nil && instance.Status == "running" {
			ip := publicIP(instance)
			if ip != "" {
				dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
				cancel()
				if dialErr == nil {
					_ = conn.Close()
					return instance, nil
				}
			}
		}
		timer := time.NewTimer(4 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Instance{}, ctx.Err()
		case <-timer.C:
		}
	}
	return Instance{}, fmt.Errorf("实例开机后 2 分钟内 TCP/%d 未从面板服务器连通", port)
}

func (s *Server) replaceIPFromBoot(ctx context.Context, account string, instance Instance, port int, provider string, useProxy bool) (Instance, *IPChange, error) {
	if s.instanceChangingIP(account, instance.ID) {
		return Instance{}, nil, errors.New("该实例已有换 IP 任务正在运行")
	}
	oldIP := publicIP(instance)
	if oldIP == "" {
		return Instance{}, nil, errors.New("开机后没有可更换的公网 IPv4")
	}
	jobID := "ip-boot-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	op := &IPChange{Job: Job{ID: jobID, Kind: "ip_change", Status: "queued", InstanceID: instance.ID, AccountID: account, OldIP: oldIP}, Original: instance, CheckPort: port, ChinaProbe: true, ChinaProvider: provider, UseProxy: useProxy}
	if s.credentials != nil {
		if raw, ok := s.credentials.token("node-binding-" + account + "/" + strconv.Itoa(instance.ID)); ok {
			op.Job.TargetID, _ = strconv.Atoi(raw)
		}
	}
	s.mu.Lock()
	for _, current := range s.jobs {
		if current.Kind == "ip_change" && current.AccountID == account && current.InstanceID == instance.ID && (current.Status == "queued" || current.Status == "running") {
			s.mu.Unlock()
			return Instance{}, nil, errors.New("该实例已有换 IP 任务正在运行")
		}
	}
	s.jobs[jobID] = op.Job
	s.mu.Unlock()
	if err := s.saveIPChange(op); err != nil {
		s.mu.Lock()
		delete(s.jobs, jobID)
		s.mu.Unlock()
		return Instance{}, nil, errors.New("无法保存开机自动换 IP 任务")
	}
	runErr := s.runIPChange(ctx, op)
	current, refreshErr := s.ipInstance(ctx, account, instance.ID)
	if refreshErr != nil {
		if runErr != nil {
			return instance, op, runErr
		}
		return instance, op, refreshErr
	}
	return current, op, runErr
}
