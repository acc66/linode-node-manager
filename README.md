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
- Linode 多账号管理，下拉选择账号移除，首页按绑定代理查询余额及赠金；创建、开机、关机、重启、删除实例；显示 IP、地区和套餐；Root 密码加密保存，现有实例可手动导入 SSH 密码
- wp2 管理员登录同步全部节点（支持动态码），会话加密保存；兼容 muKey 节点列表接口
- HTTP/HTTPS/SOCKS5 代理池加密保存，可选择账号绑定，新账号直接选择池内代理；支持名称及完整地址修改，保留账号绑定并校验独占冲突；通过余额测试验证，创建和开关机可选代理或直连，失败不自动回退
- 搜索并多选 wp2 节点后批量安装：保留同机其他节点配置，Hysteria2 UDP 端口跳跃、纯 WS VLESS 防探测按配置启用；发行文件校验、证书续期与失败恢复
- DNS Key 按域名加密保存，支持读取权限验证、启用/暂停、精确子域名 A/AAAA 更新、Cloudflare 灰云与 DNS 生效等待
- 手机适配界面：服务器卡片、底部导航、折叠配置；wp2 节点默认折叠、搜索、每页 10 条显示
- SSH 获取 CPU、内存、磁盘、服务状态、实时上下行速率和系统网卡累计流量；页面可立即采样
- Telegram 网页设置 Bot Token/Chat ID、提醒开关、测试消息；离线、恢复、资源异常及服务异常通知
- 在原实例申请额外公网 IPv4，验证新地址后释放旧地址并更新 DNS；保留原实例磁盘，不创建临时实例
- 默认每分钟监控 CPU、内存、磁盘、网卡速率和服务状态；优先用面板加密保存的实例 Root 密码，最多并发探测 6 台
- 浏览器使用账号密码表单登录，支持自动填充、记住登录 30 天及退出（公网必须使用 HTTPS）；自动化 API 仍支持 `Authorization: Bearer ADMIN_TOKEN`

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
默认 Go 进程只映射到本机 `127.0.0.1:8000`。**不要把 8000 直接映射到公网**；公网使用项目内置的 Caddy HTTPS 反向代理。浏览器进入账号密码登录页，支持浏览器保存和自动填充，不需要在网页填写 API Token。

### 公网 HTTPS + 账号密码登录
1. 在域名 DNS 将 `panel.example.com` 的 A/AAAA 记录指向管理机公网 IP，开放 TCP 80、443（可选 UDP 443）。
2. 在 `.env` 中设置 `PANEL_DOMAIN=panel.example.com`、`ADMIN_USERNAME=admin`、`ADMIN_PASSWORD=至少12位的独立强密码`。不要使用之前在聊天里公开的凭据。
3. 启动：
```bash
docker compose --profile public up -d --build
docker compose --profile public ps
docker compose --profile public logs --tail=100 caddy manager
```
4. 浏览器访问 `https://panel.example.com`，输入账号密码。Caddy 自动申请和续期有效的 TLS 证书，前提是公网 DNS/端口可达。**不要用 HTTP://公网IP:8000 登录**，未加密的 HTTP 会泄露密码。

可选：如果已有 HTTPS 反向代理，继续使用默认 Docker Compose 服务并把代理指向 `127.0.0.1:8000`，转发原始 Host / HTTPS 请求头。

登录页支持浏览器密码管理器保存账号密码；勾选“记住登录”后通过 HttpOnly Cookie 保持 30 天会话，密码不写入 localStorage。不勾选时使用最长 12 小时的浏览器会话。页面可退出登录，修改管理员密码会使旧会话失效。登录失败不会按次数锁定。若公网可访问，请额外优先启用 VPN / IP 白名单。

如果 HTTPS 登录提示“登录来源无效”，检查反向代理是否保留原始 Host（Nginx 可设置 `proxy_set_header Host $http_host;`）。当代理必须改写 Host 时，在 manager 服务的 `.env` 中将 `PANEL_DOMAIN` 设为浏览器访问的实际域名（例如 `ld.seox9.com`，非标准 HTTPS 端口需一并填写），然后重建并重启 manager。登录和后续 API 会接受该配置域名的 HTTPS 来源；不会信任客户端提供的 `X-Forwarded-Host`。

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

## 独立补号页面与账户池

登录后访问 `/refill`（首页也有入口）。共用当前管理员登录、加密账户、代理池和 DNS 配置；没有额外开放端口。自动补号默认关闭，配置完整并确认费用后启用。实例和额外 IPv4 均可能计费。

- **切号条件**：Linode API 返回可核实的 JSON 错误，确认 Token 无效（401）或操作权限不足（403）时，直接进入候选检测；连接失败或超时须连续三轮，每轮至少间隔一分钟，恢复后清零。默认每分钟检查，间隔可配置。失败计数持久保存，刷新页面不会增加计数。限流（429）和服务端错误（5xx）先等待，不直接切号；代理/出口检查异常不会回退直连，也不会伪装成 Token 错误。
- **候选账号预检**：按账户池顺序，先通过该账号独占代理调用 `GET /account` 和 `GET /linode/instances?page_size=25`，核实认证、账单读取、实例读取和可用估算额度。检测失败的 401/403 跳过；连接异常重试三次后等待，不把整个池快速跳完。只读检查不会创建测试机器，也不能保证写权限、资源配额和地区容量；真实创建明确返回 401/403 时才继续下一账号。
- **避免重复计费**：每次真实建机前持久保存创建意图、唯一标签及 Root 密码。超时、5xx 或响应异常可能已创建资源，此时暂停核对，禁止立即换号重复创建。恢复时按已保存标签寻找唯一实例，不重发创建。队列耗尽时暂停并提醒。
- **额度与流量**：额度低于提醒阈值时只通知，不触发切号；估算按适用赠金、有效期、当月上限、余额和未结算费用计算，可能保守提前提醒。流量只供手动查询；旧机 TCP 不参与切号。已移除流量阈值、预留预测和流量紧急停机，旧配置会迁移为 API 检查模式。
- **接替顺序**：当前账号异常 → 检测后续账号 → 自动建机 → 等待运行及管理机 SSH 可达 → 阿里云国内机检查新 IP → 检查通过后执行开机脚本 → 验证业务端口 → 更新指定业务子域名 DNS → 记录接替结果 → 按策略保留或请求关闭旧机。
- **持续换 IP**：新 IP 在管理机可达、国内连续不可达时，按设置串行申请并检查候选 IP，不设次数上限，每轮间隔 15 秒。候选失败后，必须读回确认原实例恢复为原单一 IPv4 才继续。探测机故障、权限或 IP 配额不足、余额不足、分配结果不明、恢复无法确认均暂停；不把这些错误当作被墙。任务没有固定总时限，可用“暂停 / 安全停止”中止；已发送的云请求和创建意图保留供核对。
- **开机脚本**：新建接替实例以及从本页面开机时，在 IP 检查通过后经 SSH 执行，可使用 `LNM_ACCOUNT_ID`、`LNM_INSTANCE_ID`、`LNM_IPV4`。脚本失败不自动重试；人工恢复可能再次执行，须保持幂等。业务文件和数据库需在脚本中迁移。脚本输出不保存在日志，避免回显密钥。
- **账户隔离和出口历史**：每个账号绑定独占代理，补号请求强制走代理。通过代理查询公网出口 IP（默认 `https://api.ipify.org?format=json`，不发送 Linode Token），加密记录 IP、代理主机端口、首次/最近检测和次数。不同账号共用已记录出口时阻止请求；历史在移除账号后保留。可用 `EGRESS_CHECK_URL` 指向返回 `{"ip":"公网IP"}` 的自有 HTTPS 服务。出口观察和独占绑定不保证平台无法关联账号。
- **旧机与恢复**：旧机默认保留，不自动删除磁盘；可选择接替后请求关机，关机仍计费。原账号 Token 失效导致无法关机时记录警告，不撤销已成功的接替。配置、API 检查、阶段、创建标签、待建实例密码和最近 200 条日志均加密持久保存。进程重启发现未完成操作时暂停，不重放建机或脚本。

页面提供每个账号的“测试 API”和最近检查结果，手动测试不会推进自动失败计数。接口沿用管理员认证：`POST /api/accounts/{id}/api-check`、`GET/PUT /api/refill`、`POST /api/refill/{run,resume,pause,probe,boot,change-ip}`、`GET/PUT /api/account-pool`、`POST /api/accounts/{id}/egress`。付费动作要求 `{"confirm_billing":true}`。

检查命令：`go test -race ./...`、`go vet ./...`、`node tests/dashboard.test.cjs`、`node tests/refill.test.cjs`。自动化测试不创建真实收费资源；真实 Linode 配额申请、SSH、DNS 接替及国内网络仍需按实际配置联调。
