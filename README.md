# Linode Node Manager — Go

独立的 Go 1.22+ Linode 运维面板。主程序：`main.go`，不再使用 Python FastAPI。当前版本为 Go MVP，未完成真实 Linode/SSH/TG 联调。

## 已实现
- Linode 实例列表、开机、关机、重启（Linode v4 API）
- wp2 的 `GET /mod_mu/nodes?key=...` 节点列表（仅输出 id/name/sort/status）
- 通过严格 SSH 主机密钥验证运行 XboardNode-Plus 安装脚本（node 模式）
- SSH 获取 CPU、内存、磁盘、uptime 和 systemd 服务状态
- Telegram 离线、恢复、资源异常及服务异常通知
- HTTP 管理接口需 `Authorization: Bearer ADMIN_TOKEN`

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
默认监听 `127.0.0.1:8000`，需要通过 HTTPS 反向代理或 SSH 隧道访问。不要将管理端口直接暴露公网。

必填：`ADMIN_TOKEN`、`LINODE_TOKEN`、`WP2_BASE_URL`、`WP2_API_TOKEN`。wp2 源码已确认 `/mod_mu/nodes` 使用查询参数 `key`，且可能受 `WebAPI` 与 `checkNodeIp` 配置限制。已在聊天中公开的密钥请轮换，不要提交到 GitHub。

可选：`MONITOR_ENABLED=true`、`MONITOR_INTERVAL=60`、`TG_BOT_TOKEN`、`TG_CHAT_ID`。

## 直接编译
```bash
go build -o linode-node-manager .
./linode-node-manager
```

## 测试
GitHub Actions 执行 `go test ./...`、`go vet ./...`、`go build ./...` 和 Docker 构建。CI 提交不代表已通过；请查看 Actions 结果。
