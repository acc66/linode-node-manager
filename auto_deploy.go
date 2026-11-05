package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed deploy_node.py
var deployPython string

func deploymentScript(base, token string, nodeID int, instance Instance) string {
	payload, _ := json.Marshal(map[string]any{"panel": base, "token": token, "node_id": nodeID, "ip": publicIP(instance), "ipv6": instance.IPv6})
	return "set -e\nexport DEBIAN_FRONTEND=noninteractive\nif ! command -v python3 >/dev/null || ! command -v openssl >/dev/null; then\n if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3 ca-certificates openssl; else echo '自动部署当前要求 Debian/Ubuntu，或预装 python3/openssl'; exit 1; fi\nfi\npython3 - <<'XN_AUTODEPLOY'\n" + deployPython + "\nimport base64\npayload=json.loads(base64.b64decode(" + strconv.Quote(base64.StdEncoding.EncodeToString(payload)) + "))\ntry:\n    deploy(payload)\nexcept Exception as error:\n    message=str(error).replace(payload['token'],'[REDACTED]')\n    print('部署失败：'+message,flush=True)\n    raise SystemExit(1)\nXN_AUTODEPLOY\n"
}
func (s *Server) deploySSH(ctx context.Context, account string, instance Instance, script string) (string, error) {
	if s.sshRun != nil {
		return s.runSSH(ctx, publicIP(instance), script)
	}
	key := env("SSH_PRIVATE_KEY_PATH", "/run/secrets/linode_ssh_key")
	known := env("SSH_KNOWN_HOSTS_PATH", "/run/secrets/known_hosts")
	if _, err := os.Stat(key); err == nil {
		if _, err := os.Stat(known); err == nil {
			return ssh(ctx, publicIP(instance), script)
		}
	}
	if s.credentials == nil {
		return "", errors.New("没有 SSH 密钥，也没有加密保存的 Root 密码")
	}
	if account == "" {
		account = "legacy"
	}
	password, ok := s.credentials.token(account + "/" + strconv.Itoa(instance.ID))
	if !ok {
		return "", errors.New("该实例没有保存的 Root 密码，请使用本面板创建的服务器或配置 SSH 密钥")
	}
	dir := env("SSH_BOOTSTRAP_DIR", "/data/ssh-bootstrap")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	helper, err := os.CreateTemp(dir, "askpass-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(helper.Name())
	if err := helper.Chmod(0700); err != nil {
		helper.Close()
		return "", err
	}
	if _, err := helper.WriteString("#!/bin/sh\nprintf '%s\\n' \"$XN_SSH_PASSWORD\"\n"); err != nil {
		helper.Close()
		return "", err
	}
	helper.Close()
	// Trust on first use for password bootstrap; persisted keys must match later.
	cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=no", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile="+filepath.Join(dir, "known_hosts"), "-o", "ConnectTimeout=15", "root@"+publicIP(instance), "bash -s")
	cmd.Env = append(os.Environ(), "SSH_ASKPASS="+helper.Name(), "SSH_ASKPASS_REQUIRE=force", "DISPLAY=xn:0", "XN_SSH_PASSWORD="+password)
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	return strings.ReplaceAll(string(output), password, "[REDACTED]"), err
}
