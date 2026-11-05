# Linode Node Manager

独立的 Linode API 云服务器管理网站（MVP）。

## 功能
- 列出实例及其 IP、状态
- 创建付费 Linode 实例（需要显式确认）
- 开机、关机、重启、删除实例
- 使用管理员 Bearer Token 保护 API
- Docker Compose 部署，默认仅监听本机端口

> **注意：** wp2 API 对接、XboardNode-Plus 自动部署及节点在线监控尚未实现。不要将本项目直接暴露到公网；建议使用 HTTPS 反向代理、访问控制和限流。

## 部署
```bash
cp .env.example .env
# 编辑 .env：设置 LINODE_TOKEN 和高强度 ADMIN_TOKEN
chmod 600 .env
docker compose up -d --build
```

使用 SSH 隧道访问 `http://127.0.0.1:8000`，或配置受保护的 HTTPS 入口。

Linode API Token 需要具有实例管理权限；创建实例会产生费用，删除实例会永久销毁相关数据。

## wp2 对接及在线安装（实验性）
设置 `.env`：
```ini
WP2_BASE_URL=https://api10.seox9.com
WP2_API_TOKEN=在服务器本地填写新生成的通信密钥
WP2_NODES_PATH=
WP2_AUTH_HEADER=Authorization
WP2_AUTH_SCHEME=Bearer
```
**WP2_NODES_PATH 目前必须按 wp2 源码中实际节点列表 API 填写。** 由于私有 wp2 仓库路由尚未核实，暂不提供猜测的路径。部分 wp2 站点的后端通信 token 与后台管理 token 不同，必须验证权限与接口返回结构。

安装到**已存在且运行中**的 Linode：面板会通过 SSH 连接实例公网 IP，运行 acc66/XboardNode-Plus 的 Linux 安装脚本，支持 node/machine 模式。请确保服务器系统、安装脚本版本和面板通信协议兼容。

在管理服务器上创建 `secrets/` 目录，放入 `linode_ssh_key`（0600）及 `known_hosts`（已**通过可信渠道验证**的 SSH 主机指纹）；这些文件不会被提交到 GitHub。创建实例时使用与私钥对应的 SSH 公钥。默认 SSH 用户 root。Docker Compose 将只读挂载 secrets。

```bash
mkdir -p secrets
chmod 700 secrets
# 安全地把 SSH 私钥放到 secrets/linode_ssh_key
chmod 600 secrets/linode_ssh_key
# 验证主机指纹后写入 secrets/known_hosts
docker compose up -d --build
```

注意：SSH 首次部署需要先验证主机指纹。当前安装任务仅保存在内存，重启管理容器后任务历史会丢失；不应将此 MVP 当作生产级任务队列。API Token 不会上传至公开仓库。若之前在聊天中公开过 Token，请先轮换。
