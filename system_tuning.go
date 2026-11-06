package main

import (
	"context"
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

func (s *Server) canTune(account string, id int) bool {
	if s.passwordSaved(account, id) {
		return true
	}
	_, keyErr := os.Stat(env("SSH_PRIVATE_KEY_PATH", "/run/secrets/linode_ssh_key"))
	_, knownErr := os.Stat(env("SSH_KNOWN_HOSTS_PATH", "/run/secrets/known_hosts"))
	return keyErr == nil && knownErr == nil
}
func (s *Server) tuneNode(ctx context.Context, account string, instance Instance) (string, error) {
	var output string
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		output, err = s.deploySSH(ctx, account, instance, systemTuningScript)
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
	if s.skipBootTuning {
		return ""
	}
	if account == "" {
		account = "legacy"
	}
	if !s.canTune(account, id) {
		return ""
	}
	jobID := "boot-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	job := Job{ID: jobID, Kind: "boot_tuning", AccountID: account, InstanceID: id, Status: "queued", Log: "等待实例运行，配置 BBR 与 nofile…\n"}
	s.mu.Lock()
	s.jobs[jobID] = job
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(useProxyContext(context.Background(), useProxy), 10*time.Minute)
		defer cancel()
		instance, err := s.waitIPInstance(ctx, account, id, func(i Instance) bool { return i.Status == "running" && publicIP(i) != "" })
		output := ""
		if err == nil {
			output, err = s.tuneNode(ctx, account, instance)
		}
		job.Log += output
		job.Status = "success"
		if strings.Contains(output, "BBR_UNSUPPORTED") {
			job.Status = "partial"
		}
		if err != nil {
			job.Status = "failed"
			job.Log += "\n开机优化失败，请核对 SSH：" + err.Error()
		}
		s.mu.Lock()
		s.jobs[jobID] = job
		s.mu.Unlock()
	}()
	return jobID
}
