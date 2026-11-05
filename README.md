# Linode Node Manager — Go

独立的 Go 1.22+ Linode 运维面板。主程序：`main.go`，不再使用 Python FastAPI。当前版本为 Go MVP，未完成真实 Linode/SSH/TG 联调。

## 已实现
- Linode 实例列表、开机、关机、重启（Linode v4 API）
- wp2 的 `GET /mod_mu/nodes?key=...` 节点列表（仅输出 id/name/sort/status）
- 通过严格 SSH 主机密钥验证运行 XboardNode-Plus 安装脚本（node 模式）
- SSH 获取 CPU、内存、磁盘、uptime 和 systemd 服务状态
- Telegram 离线、恢复、资源异常及服务异常通知
- 浏览器使用 HTTP Basic 账号密码登录（必须通过 HTTPS 公网访问），自动化 API 仍支持 `Authorization: Bearer ADMIN_TOKEN`

## 暂未移植 / 局限
旧 Python 版的创建/删除实例、机器模式安装、SQLite 任务记录尚未移植；当前监控快照与安装任务保存在内存中，进程重启后丢失。监控轮询按实例顺序执行，不适合大规模服务器。没有历史图表或外部独立监控；管理服务器自身离线时无法发送告警。

## Debian 12 / Docker
```bash
git clone https://github.com/acc66/linode-node-manager.git
cd linode-node-manager
cp .env.example .env
nano .env
mkdir -p secrets && chmod 700 secrets
# 配置 secrets/linode_ssh_key (chmod 600) 和已核实主机指纹的 secrets/known_hosts
docker compose up -d --build
docker compose logs --tail=100 manager
```
默认 Go 进程只映射到本机 `127.0.0.1:8000`。**不要把 8000 直接映射到公网**；公网使用项目内置的 Caddy HTTPS 反向代理。浏览器会弹出账号密码登录框，不再要求在网页填写 API Token。

### 公网 HTTPS + 账号密码登录
1. 在域名 DNS 将 `panel.example.com` 的 A/AAAA 记录指向管理机公网 IP，开放 TCP 80、443（可选 UDP 443）。
2. 在 `.env` 中设置 `PANEL_DOMAIN=panel.example.com`、`ADMIN_USERNAME=admin`、`ADMIN_PASSWORD=至少12位的独立强密码`。不要使用之前在聊天里公开的凭据。
3. 启动：
```bash
docker compose --profile public up -d --build
docker compose --profile public ps
docker compose --profile public logs --tail=100 caddy manager
```
4. 浏览器访问 `https://panel.example.com`，输入账号密码。Caddy 自动申请和续期有效的 TLS 证书，前提是公网 DNS/端口可达。**不要用 HTTP://公网IP:8000 登录**，Basic Auth 的密码只经过 Base64 编码，未加密的 HTTP 会泄露密码。

可选：如果已有 HTTPS 反向代理，继续使用默认 Docker Compose 服务并把代理指向 `127.0.0.1:8000`，转发原始 Host / HTTPS 请求头。

浏览器登录 8 次失败会按来源连接 IP 暂停登录 15 分钟；浏览器原生 Basic 认证不会提供可靠的一键退出，可关闭浏览器会话或清除站点认证信息。若公网可访问，请额外优先启用 VPN / IP 白名单。

必填：浏览器登录使用 `ADMIN_USERNAME`、`ADMIN_PASSWORD`；自动化 API 使用 `ADMIN_TOKEN`；业务使用 `LINODE_TOKEN`、`WP2_BASE_URL`、`WP2_API_TOKEN`。wp2 源码已确认 `/mod_mu/nodes` 使用查询参数 `key`，且可能受 `WebAPI` 与 `checkNodeIp` 配置限制。已在聊天中公开的密钥请轮换，不要提交到 GitHub。

可选：`MONITOR_ENABLED=true`、`MONITOR_INTERVAL=60`、`TG_BOT_TOKEN`、`TG_CHAT_ID`。

## 直接编译
```bash
go build -o linode-node-manager .
./linode-node-manager
```

## 测试
GitHub Actions 执行 `go test ./...`、`go vet ./...`、`go build ./...` 和 Docker 构建。CI 提交不代表已通过；请查看 Actions 结果。
