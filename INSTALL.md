# Linode Node Manager：Debian 12 详细安装指南

> 适用于本仓库的 Go 版本管理面板。推荐 Docker Compose + Caddy HTTPS。**请勿把 8000 端口直接开放公网**。所有 Linode 开关机和安装按钮都可能对真实服务器产生作用，请仅在明确确认目标后使用。

## 1. 环境要求

- 一台运行 Debian 12 的 Linux 服务器，建议至少 1 vCPU、1 GB 内存，具有公网 IPv4。
- 管理员 SSH 权限，已安装 Docker Engine 与 Docker Compose v2 插件。
- 一个你控制 DNS 的域名，例如 `panel.example.com`，A 记录指向管理机公网 IPv4；如果配置 AAAA，确保 IPv6 也确实可达。
- 服务器及云防火墙允许 TCP 80/443 入口用于 HTTPS 签发、续期及访问；可选 UDP 443。
- 不需要在代码文件或 GitHub 填写任何 Linode / wp2 / Telegram 私钥或 Token。

## 2. 安装 Docker

以 root 或具有 sudo 权限的 Debian 12 用户运行：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git gnupg
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker --version
sudo docker compose version
```

如果系统已有 Docker 与 `docker compose`，跳过本节。不要在未审阅的情况下执行第三方一键安装脚本。

## 3. 下载项目

### 方式 A：GitHub 源码（推荐，自动 Docker 构建）

```bash
git clone https://github.com/acc66/linode-node-manager.git
cd linode-node-manager
```

后续升级执行 `git pull --ff-only origin main`。

### 方式 B：GitHub Actions 编译压缩包

进入 [GitHub Actions](https://github.com/acc66/linode-node-manager/actions/workflows/smoke.yml)，打开最近一次 **绿色成功** 的运行，找到底部 **Artifacts**，下载 `linode-node-manager-linux-builds`（需要登录 GitHub；保存期限受 Actions 设置限制）。

Artifact ZIP 内含：
- `linode-node-manager-linux-amd64.tar.gz`：常见 Intel/AMD x86_64 Linux；
- `linode-node-manager-linux-arm64.tar.gz`：ARM64 Linux；
- `linode-node-manager-docker-source.tar.gz`：用于 Docker 构建的源码；
- `SHA256SUMS`：文件校验和。

下载到本地后，先解压 ZIP，再选择对应的 .tar.gz。使用 `sha256sum -c SHA256SUMS` 校验。如果走方式 A，就无需下载压缩包。

**注意**：单独编译好的 Go 二进制不包含 SSH 客户端和 Python 3；使用它进行监控/安装时，需要在管理机额外安装 `openssh-client`、`python3`。更建议用方式 A 的 Docker Compose。

## 4. 配置账号密码、API 与域名

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

在 `.env` 中重点填写（以下均为占位符，**不要复制示例密码当真实密码**）：

```dotenv
PANEL_DOMAIN=panel.example.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD=REPLACE_WITH_UNIQUE_LONG_PASSWORD
ADMIN_TOKEN=REPLACE_WITH_DIFFERENT_RANDOM_API_TOKEN
LINODE_TOKEN=REPLACE_WITH_NEW_LINODE_TOKEN
WP2_BASE_URL=https://your-wp2-api.example.com
WP2_API_TOKEN=REPLACE_WITH_WP2_TOKEN
WP2_NODES_PATH=/mod_mu/nodes
MONITOR_ENABLED=false
MONITOR_INTERVAL=60
TG_BOT_TOKEN=
TG_CHAT_ID=
```

- `ADMIN_USERNAME` / `ADMIN_PASSWORD`：浏览器访问 `https://panel.example.com` 时使用；密码至少 12 字符，建议生成 24+ 位强随机密码。
- `ADMIN_TOKEN`：供非浏览器调用 API，不是网页登录密码，建议与密码不同。
- 程序会在启动时校验登录配置。密码不足 12 位时会明确报错并退出；修改 `.env` 后执行 `docker compose --profile public up -d --build --force-recreate`。仅使用 API 时可同时留空用户名和密码，但必须设置 `ADMIN_TOKEN`。
- `LINODE_TOKEN`：Linode API，按功能授予最小所需权限；为此前已公开的 Token **重新生成新值**。
- `WP2_BASE_URL`：必须为 HTTPS，填写 wp2 API 根地址（不包含 `/mod_mu/nodes`）。
- `WP2_API_TOKEN`：wp2 通信密钥。某些 wp2 设置还会按来源 IP 控制访问，请在 wp2 服务端确认。
- `PANEL_DOMAIN`：写实际域名，不要写带协议的 URL；需要域名解析到当前管理服务器。
- Telegram 未配置则暂不会发送告警。资源监控需要 SSH 密钥及各被监控节点的已验证主机密钥。

生成强随机值的例子（输出只保存在你自己的终端，不要发到聊天、GitHub 或日志）：

```bash
openssl rand -hex 24
```

编辑 `.env` 时注意不要在键值两侧加空格；如果密码包含 `#`、`$`、空格等字符，Docker Compose 的解析/插值可能有特殊规则，建议使用 openssl 的十六进制随机字符串。

## 4A. 添加多个 Linode 账号（推荐）

新增的 **Linode 多账号管理** 可以在网页中保存多个账号的独立 API Token，并按账号查看实例、执行开关机或选择安装目标。

1. 在管理机执行 `openssl rand -hex 32`，将生成的随机值**仅保存在服务器本地** `.env` 的 `ACCOUNT_ENCRYPTION_KEY`，不要发送到聊天或上传 GitHub。
2. 确认 `.env` 中有：
   ```dotenv
   ACCOUNT_ENCRYPTION_KEY=请填入生成的64位随机值
   ACCOUNTS_FILE=/data/accounts.enc
   ```
3. 重新启动容器：
   ```bash
   docker compose --profile public up -d --build --force-recreate
   ```
4. HTTPS 登录网页后，找到「Linode 多账号管理」，填写账号备注和对应的新 API Token，点击「添加账号」。
5. 在下拉框选择某个账号，点击刷新后只显示该账号实例。**选择「全部账号」时只能查看，开关机和安装必须先选定账号**，避免相同 Linode 实例 ID 导致误操作。
6. 删除网页中的账号只移除本地保存的凭据，不会删除任何 Linode 云服务器。

保存位置：Docker 卷内的 `/data/accounts.enc`，采用 AES-GCM 加密存储，网页 API 不回传明文 Token。请同时备份 **加密文件及单独保存的加密密钥**，否则更换密钥后旧数据无法恢复。不要使用之前在聊天中公开过的 Token，建议每个账号授予最小权限。

如果原来的 `LINODE_TOKEN` 仍保留在 `.env`，页面会出现一个「默认账号 (.env)」；不需要这个账号时可以清空该变量，多账号功能依然可用。服务器关闭或监控通知会标记对应账号，避免账号之间串号。

## 5. 配置 SSH 监控和安装（可选）

```bash
mkdir -p secrets
chmod 700 secrets
```

程序默认读取 `./secrets/linode_ssh_key` 和 `./secrets/known_hosts`。**不要从网页复制聊天中曾公开的私钥，也不要把私钥放到 GitHub。**

将你已有且仅限相应节点使用的私钥，通过可信方式放到 `secrets/linode_ssh_key`：

```bash
chmod 600 secrets/linode_ssh_key
```

远端节点必须将对应公钥安装到目标 SSH 用户的 `authorized_keys`，并保证网络/安全组允许管理机访问 SSH 22（或服务器真实 SSH 端口）。设置 `MONITOR_SSH_USER` 为 SSH 用户名（默认 root）。

`known_hosts` 要使用**经独立渠道核验指纹**的服务器主机密钥。可以使用 `ssh-keyscan` 获取待验证记录，但**不能把未经核实的扫描结果直接信任**。核实后保存到 `secrets/known_hosts`。

安装接口会下载并执行 XboardNode-Plus 远程脚本；请先审查其源码及权限，真实安装必须由你确认再点击。

## 6. 启动公网 HTTPS 面板

```bash
docker compose --profile public config --quiet
docker compose --profile public up -d --build
docker compose --profile public ps
docker compose --profile public logs --tail=100 manager caddy
```

Caddy 对公网提供 80/443，Go 管理程序仍只映射到服务器本机的 `127.0.0.1:8000`，不会直接对公网发布 8000。

当域名解析与端口正确时，Caddy 会自动获取 HTTPS 证书。浏览器打开：

```text
https://panel.example.com
```

第一次访问会弹出浏览器原生账号密码登录框，输入 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD`。

如果只有公网 IP、没有域名：**不建议通过 HTTP://IP:8000 输入账号密码**。可以先通过 SSH 隧道使用本机端口，或申请域名配置 HTTPS。

## 7. 验证是否成功

```bash
docker compose --profile public ps
curl -I https://panel.example.com/
```

未登录的 HTTPS 请求返回 `HTTP 401 Unauthorized` 是**正常的安全行为**；正确的浏览器账号密码应该能打开面板。

需要检查 API 时，请在终端交互式输入密码，避免直接把密码写进 shell history：

```bash
curl --user admin https://panel.example.com/api/health
```

它会提示输入密码，成功后返回类似 `{"status":"ok","language":"go"}`。

可在面板中测试服务器列表和 wp2 节点下拉。**不要为了测试而点击真实开机、关机、重启或安装按钮**。完整模拟测试已在 GitHub Actions 中执行。

## 8. 开启监控和 Telegram 通知

SSH 已验证正常后，在 `.env` 配置：

```dotenv
MONITOR_ENABLED=true
MONITOR_INTERVAL=60
MONITOR_SSH_USER=root
ALERT_FAILURE_COUNT=3
ALERT_CPU_PERCENT=90
ALERT_MEMORY_PERCENT=90
ALERT_DISK_PERCENT=90
TG_BOT_TOKEN=YOUR_NEW_BOT_TOKEN
TG_CHAT_ID=YOUR_CHAT_ID
```

重新加载：

```bash
docker compose --profile public up -d
docker compose --profile public logs --tail=100 manager
```

如果更改了 `.env`，建议明确执行 `docker compose --profile public up -d --force-recreate`，确保容器接收新环境变量。

注意：这是**由管理机主动轮询 SSH** 的监控，不是节点推送心跳；管理服务器本身断网或关机时不能自行发送离线通知。服务运行状态按照 `xboard-node.service` 判断，若你的节点使用其他 systemd 单元，应修改对应探针。

## 9. 常见故障

| 现象 | 排查 |
|---|---|
| 浏览器打不开域名 | 检查 DNS A/AAAA、云防火墙 TCP 80/443、系统防火墙、Caddy 日志 |
| HTTPS 证书不成功 | 域名未指向当前 IP；80/443 被占用或被拦截；检查 `docker compose --profile public logs caddy` |
| 页面弹出账号密码 | 预期行为；没有填写时返回 401 |
| 正确密码仍返回 401 | 检查 `.env` 的 ADMIN_USERNAME/ADMIN_PASSWORD；检查长度至少 12 位；容器是否已重建 |
| 登录返回 401 | 账号或密码不正确；登录失败不再触发次数锁定，确认浏览器没有缓存旧密码 |
| Linode 列表错误 | 检查未过期的新 Linode Token、API 权限、管理机出站网络 |
| wp2 节点空/502 | 检查 HTTPS API 根地址、通信密钥、wp2 接口限制与来源 IP 白名单 |
| SSH 监控显示离线 | 检查密钥权限、known_hosts 指纹、SSH 连接与 Python 3 |
| 没有 Telegram 通知 | 检查 bot Token、chat ID，确认监控已启用且已满足告警触发条件 |

日志检查：

```bash
docker compose --profile public logs -f --tail=100 manager caddy
```

升级：

```bash
git pull --ff-only origin main
docker compose --profile public up -d --build
```

停止：

```bash
docker compose --profile public down
```

不要随意执行 `down -v`，否则会删除 Compose 管理的数据卷（包括 Caddy 证书缓存）。

## 10. 安全检查清单

- 使用 HTTPS，不把 8000 映射公网。
- 所有曾公开在聊天中的 GitHub、Linode、wp2 和 Telegram 凭据都立即撤销并轮换。
- `.env` 和 `secrets/` 不提交到 GitHub；检查文件权限。
- 为 Linode API 创建最小权限 Token。
- 推荐额外限制可访问管理面板的公网 IP 或通过 VPN。
- 操作真实云服务器前，在网页确认实例 ID 及动作。

## 11. 通过 API 创建 Linode 服务器

在「Linode 多账号管理」中添加 Token 并选择目标账号，点击「加载创建选项」。选择地区、套餐及系统镜像，填写名称和 Root 密码，再点击「创建并开机」。确认框会显示账号、地区、套餐价格与系统；确认后才发送创建请求，创建会产生费用。Token 需要拥有 Linode 创建所需的读写权限。

地区和套餐由 Linode 实时返回，显示的基础价格仅供参考，地区差价与最终账单以 Linode 为准。请求超时后先刷新实例列表检查结果，避免重复创建。

对应接口为 `GET /api/catalog/{regions|types|images}?account_id=账号ID` 和 `POST /api/instances?account_id=账号ID`。创建 JSON 包含 `label`、`region`、`type`、`image`、`root_pass`、`confirm: true`。Root 密码使用 ACCOUNT_ENCRYPTION_KEY 加密保存到 INSTANCE_CREDENTIALS_FILE（默认 /data/instance-credentials.enc）。列表只返回是否保存，点击“查看密码”后才通过已认证接口读取；请备份加密文件和密钥。创建服务器不会自动安装 XboardNode-Plus；SSH 密钥、known_hosts 与节点安装另行配置。

## 12. 实例 IP、密码和删除

列表显示 IPv4、IPv6、地区和套餐。创建后刷新列表查看启动与 IP 分配状态。通过本面板新建的实例自动加密保存 Root 密码，点击“查看密码”可查看；已有实例的密码无法从 Linode API 找回。删除实例需要输入实例 ID，成功后清除该账号对应的保存密码。删除永久移除云端实例及其磁盘。

wp2 返回空列表时运行只读诊断：`docker compose exec -T manager python3 < wp2-check.py`，输出只包含 HTTP 状态、认证结果、数据结构及节点 ID，不输出密钥或完整配置。管理机当前 muKey 与 wp2 应保持一致；来源 IP 限制需要在 wp2 端检查。

## 13. 不修改 wp2：连接管理员接口

重建管理面板后，在“wp2 节点”中填写 wp2 管理员邮箱、密码及两步动态码（如启用），点击“连接 wp2”。程序通过 `/auth/login` 登录，随后验证 `/admin/node/ajax` 的管理员权限并分页同步全部节点。

登录密码和动态码不保存；登录 Cookie 使用 ACCOUNT_ENCRYPTION_KEY 加密，存放在 INSTANCE_CREDENTIALS_FILE 中，浏览器不会收到 Cookie。会话过期后重新连接。断开连接会删除本地保存的会话，不会注销其他浏览器中的 wp2 会话。没有管理员连接时仍使用原有 muKey 接口；管理员会话过期时不会静默切回可能返回空列表的旧接口。

wp2 如启用网页验证码，当前连接表单不能完成该验证，会明确提示；不需要为此修改 wp2 认证设置。连接后不需要部署 wp2 管理视图补丁。

## 14. Linode HTTP / SOCKS5 可选代理

选择具体 Linode 账号，填写 `http://用户:密码@主机:端口` 或 `socks5://用户:密码@主机:端口`，点击“加密保存代理”。代理密码不回显。创建、开机等操作前勾选“使用所选账号的代理”；不勾选时直连。代理只作用于 Linode API，不代理 SSH、wp2 登录或远端下载。代理失败不会回退直连。删除 Linode 账号不会删除云服务器；移除默认账号会持久禁用该默认账号，原 `.env` 中的 Token 不被远端撤销。

## 15. 自动安装、证书与恢复

在“安装 XboardNode-Plus”中选择运行中的服务器和 wp2 节点，点击“自动安装并验证”并确认目标。程序自动获取节点协议/端口/域名，下载 acc66/XboardNode-Plus v1.18 的对应架构二进制并校验 SHA256，写入受限配置，设置 systemd 开机自启与故障重启，并验证服务拥有的节点监听端口。页面自动查询任务，无需输入任务 ID。

需要证书的协议使用节点域名申请 HTTP-01 证书，由 XboardNode-Plus 内置 CertMagic 自动续期和重新加载。域名解析、80 端口和云防火墙仍须正确；当前不自动修改外部 DNS 或云防火墙。UFW 已启用时会放行节点端口及申请证书所需的 TCP 80；失败恢复不撤销已新增的 UFW 放行规则。不会自动覆盖其他节点配置，也不会在证书申请失败时偷偷退回自签名。Reality 模式使用 wp2 提供的配置。

SSH 优先使用配置好的私钥与已验证主机密钥。没有私钥时使用本面板加密保存的 Root 密码自动连接，首次信任主机密钥并持久保存到 `/data/ssh-bootstrap/known_hosts`，后续密钥变更会拒绝连接。已有实例若未保存密码且未配置 SSH 密钥，无法自动登录。自动部署需要 root 与 systemd；Python/openssl 不存在时支持 Debian/Ubuntu 自动安装依赖。

安装失败时尝试恢复原程序、配置与服务状态；备份保存在远端 `/etc/XboardNode-Plus/backups`。本地健康检查只证明服务和端口运行，不证明真实客户端能够从公网连接。
