package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const domesticProbeID = "domestic-probe/0"
const chinaProbeProviderID = "china-probe-provider/0"
const chinaBootSettingsID = "china-boot-settings/0"

type ChinaBootSettings struct {
	Enabled     bool `json:"enabled"`
	Port        int  `json:"port"`
	AutoReplace bool `json:"auto_replace"`
}

func (s *Server) chinaBootSettings() (ChinaBootSettings, error) {
	settings := ChinaBootSettings{Port: 22, AutoReplace: true}
	if s.credentials == nil {
		return settings, nil
	}
	raw, ok := s.credentials.token(chinaBootSettingsID)
	if !ok {
		return settings, nil
	}
	if json.Unmarshal([]byte(raw), &settings) != nil {
		return settings, errors.New("开机 IP 检测设置损坏，请重新保存")
	}
	if settings.Port == 0 {
		settings.Port = 22
	}
	return settings, nil
}

func (s *Server) saveChinaBootSettings(settings ChinaBootSettings) error {
	if settings.Port < 1 || settings.Port > 65535 {
		return errors.New("开机检查端口必须在 1-65535 之间")
	}
	data, _ := json.Marshal(settings)
	return s.saveRootPassword("china-boot-settings", 0, "China boot IP check", string(data))
}

type DomesticProbeConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
}

var safeSSHUser = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)
var errDomesticTCPUnreachable = errors.New("国内探测机 TCP 端口不可达")

func (s *Server) domesticProbeConfig() (DomesticProbeConfig, bool, error) {
	if s.credentials == nil {
		return DomesticProbeConfig{}, false, errors.New("加密凭据存储未启用")
	}
	raw, ok := s.credentials.token(domesticProbeID)
	if !ok {
		return DomesticProbeConfig{}, false, nil
	}
	var config DomesticProbeConfig
	if json.Unmarshal([]byte(raw), &config) != nil {
		return DomesticProbeConfig{}, false, errors.New("国内探测机配置损坏，请重新保存")
	}
	return config, true, nil
}

func (s *Server) chinaProbeProvider() (string, error) {
	if s.credentials == nil {
		return "", errors.New("加密凭据存储未启用")
	}
	provider, ok := s.credentials.token(chinaProbeProviderID)
	if !ok || provider == "" {
		return "aliyun", nil
	}
	if provider != "aliyun" && provider != "iptrace" {
		return "", errors.New("国内探测方式配置无效")
	}
	return provider, nil
}

func (s *Server) chinaProbeConfigured(provider string) bool {
	switch provider {
	case "aliyun":
		_, ok, err := s.domesticProbeConfig()
		return err == nil && ok
	case "iptrace":
		if s.credentials == nil {
			return false
		}
		_, ok := s.credentials.token(ipTraceProbeID)
		return ok
	default:
		return false
	}
}

func (s *Server) setChinaProbeProvider(provider string) error {
	if provider != "aliyun" && provider != "iptrace" {
		return errors.New("请选择阿里云 SSH 或 IPTrace API")
	}
	if !s.chinaProbeConfigured(provider) {
		return errors.New("请先保存并验证该探测方式的凭据")
	}
	if err := s.saveRootPassword("china-probe-provider", 0, "China TCP probe provider", provider); err != nil {
		return err
	}
	if _, configured := s.credentials.token(chinaBootSettingsID); !configured {
		return s.saveChinaBootSettings(ChinaBootSettings{Enabled: true, Port: 22, AutoReplace: true})
	}
	return nil
}

func validDomesticProbeConfig(config DomesticProbeConfig) error {
	if net.ParseIP(config.Host) == nil || net.ParseIP(config.Host).To4() == nil {
		return errors.New("国内探测机请填写有效的 IPv4 地址")
	}
	if config.Port < 1 || config.Port > 65535 {
		return errors.New("SSH 端口必须在 1-65535 之间")
	}
	if !safeSSHUser.MatchString(config.User) {
		return errors.New("SSH 用户名格式无效")
	}
	if strings.TrimSpace(config.Password) == "" {
		return errors.New("请填写国内探测机 SSH 密码")
	}
	if strings.ContainsAny(config.Password, "\r\n") {
		return errors.New("SSH 密码不能包含换行符")
	}
	return nil
}

func (s *Server) domesticProbeSSH(ctx context.Context, config DomesticProbeConfig, script string) (string, error) {
	if s.sshRun != nil {
		return s.runSSH(ctx, config.Host, script)
	}
	dir := filepath.Join(env("SSH_BOOTSTRAP_DIR", "/data/ssh-bootstrap"), "domestic-probe")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("无法创建国内探测机 SSH 状态目录")
	}
	secret, err := os.CreateTemp(dir, "password-*")
	if err != nil {
		return "", errors.New("无法准备国内探测机 SSH 登录")
	}
	defer os.Remove(secret.Name())
	if err := secret.Chmod(0600); err != nil {
		secret.Close()
		return "", errors.New("无法保护国内探测机 SSH 密码文件")
	}
	if _, err := secret.WriteString(config.Password + "\n"); err != nil {
		secret.Close()
		return "", errors.New("无法准备国内探测机 SSH 登录")
	}
	_ = secret.Close()
	helper, err := os.CreateTemp(dir, "askpass-*")
	if err != nil {
		return "", errors.New("无法准备国内探测机 SSH 登录")
	}
	defer os.Remove(helper.Name())
	if err := helper.Chmod(0700); err != nil {
		helper.Close()
		return "", errors.New("无法保护国内探测机 SSH 登录文件")
	}
	if _, err := helper.WriteString("#!/bin/sh\ncat " + shellQuote(secret.Name()) + "\n"); err != nil {
		helper.Close()
		return "", errors.New("无法准备国内探测机 SSH 登录")
	}
	_ = helper.Close()
	knownHosts := filepath.Join(dir, "known_hosts")
	args := []string{"-p", strconv.Itoa(config.Port), "-o", "BatchMode=no", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + knownHosts, "-o", "ConnectTimeout=12", "-o", "ServerAliveInterval=5", config.User + "@" + config.Host, "bash -s"}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS="+helper.Name(), "SSH_ASKPASS_REQUIRE=force", "DISPLAY=xn:0")
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	text := strings.ReplaceAll(string(output), config.Password, "[REDACTED]")
	if err != nil {
		return text, fmt.Errorf("无法通过 SSH 连接国内探测机 %s:%d（请检查 SSH 端口、用户名、密码和防火墙）", config.Host, config.Port)
	}
	return text, nil
}

func (s *Server) testDomesticProbeSSH(ctx context.Context, config DomesticProbeConfig) error {
	if err := validDomesticProbeConfig(config); err != nil {
		return err
	}
	output, err := s.domesticProbeSSH(ctx, config, "printf 'DOMESTIC_PROBE_SSH_OK\\n'\n")
	if err != nil {
		return err
	}
	if !strings.Contains(output, "DOMESTIC_PROBE_SSH_OK") {
		return errors.New("国内探测机 SSH 已连接，但远程命令没有返回确认标记")
	}
	return nil
}

func (s *Server) checkDomesticTCP(ctx context.Context, targetIP string, port int) (string, error) {
	config, configured, err := s.domesticProbeConfig()
	if err != nil {
		return "", err
	}
	if !configured {
		return "", errors.New("尚未配置国内探测机，请到“国内探测”设置填写 SSH 信息")
	}
	if err := validDomesticProbeConfig(config); err != nil {
		return "", err
	}
	ip := net.ParseIP(targetIP)
	if ip == nil || ip.To4() == nil || port < 1 || port > 65535 {
		return "", errors.New("待测 IP 或 TCP 端口无效")
	}
	// IP and port are strictly validated above, so they cannot inject shell syntax.
	script := fmt.Sprintf("if timeout 7 bash -c 'true >/dev/tcp/%s/%d' >/dev/null 2>&1; then echo DOMESTIC_TCP_OPEN; else echo DOMESTIC_TCP_CLOSED; fi\n", ip.To4().String(), port)
	output, err := s.domesticProbeSSH(ctx, config, script)
	if err != nil {
		return output, err
	}
	if strings.Contains(output, "DOMESTIC_TCP_OPEN") {
		return output, nil
	}
	return output, fmt.Errorf("%w：阿里云探测机无法连接 %s:%d", errDomesticTCPUnreachable, ip.To4().String(), port)
}

func (s *Server) checkChinaTCP(ctx context.Context, provider, targetIP string, port int) (string, error) {
	if !s.chinaProbeConfigured(provider) {
		return "", errors.New("尚未配置并选择国内探测方式")
	}
	if provider == "iptrace" {
		return s.checkIPTraceTCP(ctx, targetIP, port)
	}
	return s.checkDomesticTCP(ctx, targetIP, port)
}

func (s *Server) domesticProbeSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config, configured, err := s.domesticProbeConfig()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		provider, _ := s.chinaProbeProvider()
		send(w, 200, map[string]any{"configured": configured, "host": config.Host, "port": config.Port, "user": config.User, "selected": provider == "aliyun", "iptrace_configured": s.chinaProbeConfigured("iptrace"), "selected_provider": provider})
	case http.MethodPost:
		var config DomesticProbeConfig
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&config) != nil {
			fail(w, 400, "国内探测机配置格式无效")
			return
		}
		config.Host = strings.TrimSpace(config.Host)
		config.User = strings.TrimSpace(config.User)
		if config.Password == "" {
			if old, ok, err := s.domesticProbeConfig(); err == nil && ok {
				config.Password = old.Password
			}
		}
		if err := validDomesticProbeConfig(config); err != nil {
			fail(w, 400, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		if err := s.testDomesticProbeSSH(ctx, config); err != nil {
			fail(w, 502, err.Error())
			return
		}
		data, _ := json.Marshal(config)
		if err := s.saveRootPassword("domestic-probe", 0, "Domestic TCP probe", string(data)); err != nil {
			fail(w, 500, "SSH 探测机配置加密保存失败")
			return
		}
		if err := s.setChinaProbeProvider("aliyun"); err != nil {
			fail(w, 500, "探测机已验证并保存，但启用失败")
			return
		}
		send(w, 200, map[string]any{"saved": true, "host": config.Host, "port": config.Port, "user": config.User})
	case http.MethodDelete:
		if s.credentials == nil {
			fail(w, 503, "加密凭据存储未启用")
			return
		}
		if _, ok := s.credentials.token(domesticProbeID); ok {
			if err := s.credentials.remove(domesticProbeID); err != nil {
				fail(w, 500, "无法移除国内探测机配置")
				return
			}
		}
		if s.chinaProbeConfigured("iptrace") {
			_ = s.setChinaProbeProvider("iptrace")
		}
		send(w, 200, map[string]bool{"deleted": true})
	default:
		fail(w, 405, "Method not allowed")
	}
}

func (s *Server) chinaProbeProviderAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		fail(w, 405, "Method not allowed")
		return
	}
	var in struct {
		Provider string `json:"provider"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
		fail(w, 400, "国内探测方式格式无效")
		return
	}
	if err := s.setChinaProbeProvider(in.Provider); err != nil {
		fail(w, 400, err.Error())
		return
	}
	send(w, 200, map[string]string{"provider": in.Provider})
}

func (s *Server) chinaBootSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.chinaBootSettings()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		provider, _ := s.chinaProbeProvider()
		send(w, 200, map[string]any{"settings": settings, "provider": provider, "probe_configured": s.chinaProbeConfigured(provider)})
	case http.MethodPost:
		var settings ChinaBootSettings
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&settings) != nil {
			fail(w, 400, "开机 IP 检测设置格式无效")
			return
		}
		if settings.Port == 0 {
			settings.Port = 22
		}
		if settings.Enabled {
			provider, err := s.chinaProbeProvider()
			if err != nil || !s.chinaProbeConfigured(provider) {
				fail(w, 409, "请先配置并选择国内探测方式")
				return
			}
		}
		if err := s.saveChinaBootSettings(settings); err != nil {
			fail(w, 400, err.Error())
			return
		}
		send(w, 200, map[string]any{"saved": true, "settings": settings})
	default:
		fail(w, 405, "Method not allowed")
	}
}
