# Linode Node Manager — Go

**完整中文安装手册：** [INSTALL.md](INSTALL.md)（Debian 12、GitHub 编译包、账号密码、HTTPS、监控、Telegram、排错）。

独立的 Go 1.22+ Linode 运维面板。主程序：`main.go`，不再使用 Python FastAPI。当前版本为 Go MVP，尚未完成全部真实 Linode/SSH/TG 联调。

## VLESS 非法路径拉黑检查

只对 VLESS 非 TLS WebSocket 节点启用错误路径防护。访问非配置路径（例如正确路径为 `/mm`，访问 `/wrong`）会返回 nginx 蜜罐页，并把来源 IP 追加到 `/etc/XboardNode-Plus/blacklist.txt`。黑名单文件在第一次触发封禁时创建。

检查配置与日志：

```sh
sudo grep -n -A5 -B2 'guard' /etc/XboardNode-Plus/config.yml
sudo journalctl -u xboard-node.service --since today --no-pager | grep -E 'guard: (enabled|probe|banned)'
sudo cat /etc/XboardNode-Plus/blacklist.txt
```

用外部网络测试前确认端口是 VLESS WS 端口；下面请求会封禁发起请求的公网 IP：

```sh
curl -i --max-time 5 http://服务器IPv4:端口/错误路径
```

只有安装了防护代码之后新装或重装的 VLESS 节点才会带有该配置。检查不到 `guard.enabled` 时，在面板重装对应 VLESS 节点；如果日志有 `guard: enabled` 但没有 `probe/banned`，则尚未有请求命中错误路径。

## 已实现
- Linode 多账号管理及账号移除；创建、开机、关机、重启、删除实例；显示 IP、地区和套餐；Root 密码加密保存，现有实例可手动导入 SSH 密码
- wp2 管理员登录同步全部节点（支持动态码），会话加密保存；兼容 muKey 节点列表接口
- HTTP/HTTPS/SOCKS5 代理池加密保存，可选择账号绑定，新账号直接选择池内代理；通过余额测试验证绑定，创建和开关机可选代理或直连，失败不自动回退
- 搜索并多选 wp2 节点后批量安装：保留同机其他节点配置，Hysteria2 UDP 端口跳跃、纯 WS VLESS 防探测按配置启用；发行文件校验、证书续期与失败恢复
- DNS Key 按域名加密保存，支持读取权限验证、启用/暂停、精确子域名 A/AAAA 更新、Cloudflare 灰云与 DNS 生效等待
- 手机适配界面：服务器卡片、底部导航、折叠配置；wp2 节点默认折叠、搜索、每页 10 条显示
- SSH 获取 CPU、内存、磁盘、服务状态、实时上下行速率和系统网卡累计流量；页面可立即采样
- Telegram 网页设置 Bot Token/Chat ID、提醒开关、测试消息；离线、恢复、资源异常及服务异常通知
- 在原实例申请额外公网 IPv4，验证新地址后释放旧地址并更新 DNS；保留原实例磁盘，不创建临时实例
- 默认每分钟监控 CPU、内存、磁盘、网卡速率和服务状态；优先用面板加密保存的实例 Root 密码，最多并发探测 6 台
- 浏览器使用 HTTP Basic 账号密码登录（必须通过 HTTPS 公网访问），自动化 API 仍支持 `Authorization: Bearer ADMIN_TOKEN`

## 暂未移植 / 局限
机器模式安装和持久化任务历史尚未实现；当前监控快照与安装任务保存在内存中，进程重启后丢失。监控每轮最多并发探测 6 台。没有历史图表或外部独立监控；累计流量是所选网卡自计数器启动以来的数据，不是 Linode 月度账单配额，瞬时速率也可能受 250 毫秒采样窗口影响；管理服务器自身离线时无法发送告警。

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

登录失败不会按次数锁定；浏览器原生 Basic 认证不会提供可靠的一键退出，可关闭浏览器会话或清除站点认证信息。若公网可访问，请额外优先启用 VPN / IP 白名单。

必填：浏览器登录使用 `ADMIN_USERNAME`、`ADMIN_PASSWORD`；自动化 API 使用 `ADMIN_TOKEN`；业务使用 `LINODE_TOKEN`、`WP2_BASE_URL`、`WP2_API_TOKEN`。wp2 源码已确认 `/mod_mu/nodes` 使用查询参数 `key`，且可能受 `WebAPI` 与 `checkNodeIp` 配置限制。已在聊天中公开的密钥请轮换，不要提交到 GitHub。

可选：`MONITOR_ENABLED=true`、`MONITOR_INTERVAL=60`、`TG_BOT_TOKEN`、`TG_CHAT_ID`。

## 直接编译
```bash
go build -o linode-node-manager .
./linode-node-manager
```

## 测试
GitHub Actions 执行 `go test ./...`、`go vet ./...`、`go build ./...` 和 Docker 构建。CI 提交不代表已通过；请查看 Actions 结果。

无本地端口权限的环境可运行 `LINODE_TEST_IN_MEMORY=1 go test ./...`，通过内存 HTTP transport 验证同一组模拟接口；该模式不验证 TCP/TLS 连接。普通 `go test ./...` 仍使用本地 HTTPS 模拟服务。

## 自动部署前提

通过本面板创建的实例可使用已加密保存的 Root 密码自动 SSH 登录；也可以使用原有 SSH 私钥和已验证 known_hosts。密码方式首次连接采用 SSH 首次信任并保存主机密钥，之后拒绝主机密钥变更。无需再次填写节点 token、IP、Root 密码或证书参数。

TLS 域名从 wp2 节点配置获取。域名的 A/AAAA 必须指向实例，公网 TCP 80 可达，节点端口也需在云防火墙中放行。面板支持配置阿里云/Cloudflare DNS Key，按子域名自动更新解析并等待生效；未启用匹配配置时保留现有解析。新建实例默认不绑定云防火墙，可在创建前取消全端口选项；不会更改账号默认防火墙或其他实例。证书失败不退回自签名。后台协议配置、密钥及外部 DNS 权限仍需正确配置。真实公网证书签发和端到端节点连接尚未在本环境验证。

自动安装一次最多可选 20 个节点，只替换本次选中的节点并保留其他节点绑定；不覆盖非本面板管理的配置。固定版本与 SHA256 位于 `deploy_node.py`；更新发行版本时需要同步校验值。远端内置 CertMagic 负责证书续期和加载，不依赖管理面板持续运行。
