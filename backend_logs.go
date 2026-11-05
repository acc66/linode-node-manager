package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const backendLogScript = `python3 - <<'XN_LOG'
import json,subprocess
def read(*args):
 try:
  return subprocess.run(args,capture_output=True,text=True,timeout=12).stdout
 except Exception:
  return ''
state=read('systemctl','is-active','xboard-node.service').strip()
log=read('journalctl','-u','xboard-node.service','-n','80','--no-pager','-o','short-iso')
print(json.dumps({'service':state or 'unknown','log':log[-16000:] or '暂无后端日志'}))
XN_LOG
`

func (s *Server) backendLogsAPI(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account_id")
	id, err := strconv.Atoi(r.PathValue("id"))
	if account == "" || err != nil || id <= 0 {
		fail(w, 400, "请先选择账号和实例")
		return
	}
	b, status, err := s.linodeFor(r.Context(), account, "GET", "/linode/instances/"+strconv.Itoa(id), nil)
	if err != nil || status != 200 {
		fail(w, 502, "无法查询目标 Linode 实例")
		return
	}
	var instance Instance
	if json.Unmarshal(b, &instance) != nil || instance.Status != "running" || publicIP(instance) == "" {
		fail(w, 409, "需要运行中且有公网 IP 的实例")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	output, err := s.deploySSH(ctx, account, instance, backendLogScript)
	if err != nil {
		fail(w, 502, "无法读取后端日志，请检查 SSH 和服务安装状态")
		return
	}
	var result struct {
		Service string `json:"service"`
		Log     string `json:"log"`
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	decoded := false
	for i := len(lines) - 1; i >= 0; i-- {
		if json.Unmarshal([]byte(lines[i]), &result) == nil && result.Service != "" {
			decoded = true
			break
		}
	}
	if !decoded {
		fail(w, 502, "后端日志响应无效")
		return
	}
	send(w, 200, result)
}
