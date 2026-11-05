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
