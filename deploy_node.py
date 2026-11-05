"""Executed on the selected node; credentials are supplied through SSH stdin."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

VERSION = 'v1.18'
ASSETS = {
    'amd64': {'xboard-node': 'aa8dbd7a5640a5bc22c52ca6e4b6e403b4bdc0f857773e8d23ee19f1362690ef',
              'xbctl': 'f6a13a1c9e8841ade84b18d27f765e8b8b00fef54a6f7749ad57b56663972526'},
    'arm64': {'xboard-node': '7196c9e2059904c026b4d53bd7964b0aee94f3f1d43c64b29d78b38e84eb4a28',
              'xbctl': '26e3df24bdd97bbd10a4e36a52a45359e935b415c5d548d29bc0ea221892b955'},
}
ROOT = Path('/etc/XboardNode-Plus')
UNIT = Path('/etc/systemd/system/xboard-node.service')
BINDIR = Path('/usr/local/bin')


def command(*args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=240)


def wait_node_dns(domain, ip, ipv6='', wait_dns=False):
    allowed = {ip}
    if ipv6:
        allowed.add(ipv6.split('/')[0])
    deadline = time.monotonic() + (600 if wait_dns else 0)
    announced = False
    while True:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)}
        except socket.gaierror:
            addresses = set()
        if addresses and addresses <= allowed and ip in addresses:
            break
        if time.monotonic() >= deadline:
            raise ValueError('节点域名 A/AAAA 未全部指向当前实例或 DNS 缓存尚未过期，请稍后重试')
        if not announced:
            print('DNS 记录已更新，等待目标服务器解析缓存生效（最多10分钟）…', flush=True)
            announced = True
        time.sleep(10)

def node_settings(config, ip, ipv6='', wait_dns=False):
    protocol = str(config.get('server_type') or config.get('protocol') or '').lower()
    if protocol == 'v2ray':
        protocol = 'vmess'
    if protocol not in ['shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'socks', 'http', 'naive', 'mieru']:
        raise ValueError('wp2 返回不支持的节点协议')
    port = int(config.get('server_port', 0))
    if not 1 <= port <= 65535 or port == 65530:
        raise ValueError('节点端口无效或与健康检查端口冲突')
    tls = config.get('tls', 0)
    reality = str(tls) == '2'
    needs_tls = not reality and (protocol in ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'naive'] or str(tls) == '1')
    cert = {'cert_mode': 'none'}
    if needs_tls:
        tls_settings = config.get('tls_settings') or {}
        domain = str(tls_settings.get('server_name') or config.get('server_name') or config.get('domain') or '').strip().lower()
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            if not domain or '.' not in domain or any(c in domain for c in '/: *\n\r'):
                raise ValueError('TLS 节点没有有效域名，请先在 wp2 节点配置域名')
        else:
            raise ValueError('自动申请证书需要节点域名，不能使用 IP 或自动退回自签名证书')
        wait_node_dns(domain, ip, ipv6, wait_dns)
        cert = {'cert_mode': 'http', 'auto_tls': True, 'domain': domain,
                'http_port': 80, 'cert_dir': str(ROOT / 'certs')}
    return protocol, port, cert


def node_listening(pid, port):
    if not pid.isdigit() or int(pid) <= 0:
        return False
    inodes = set()
    try:
        for entry in Path('/proc/' + pid + '/fd').iterdir():
            try:
                target = os.readlink(entry)
                if target.startswith('socket:['):
                    inodes.add(target[8:-1])
            except OSError:
                pass
        for name in ['tcp', 'tcp6', 'udp', 'udp6']:
            for line in Path('/proc/net/' + name).read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[9] in inodes and int(fields[1].rsplit(':', 1)[1], 16) == port:
                    if name.startswith('udp') or fields[3] == '0A':
                        return True
    except OSError:
        return False
    return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def backend_diagnostics(payload, stage):
    print('\n── 后端服务状态与日志（'+stage+'）──', flush=True)
    try:
        state = command('systemctl', 'is-active', 'xboard-node.service', check=False).stdout.strip()
        print('后端服务状态：'+(state or 'unknown'), flush=True)
        journal = command('journalctl', '-u', 'xboard-node.service', '-n', '60', '--no-pager', '-o', 'short-iso', check=False).stdout
        print((journal or '暂无后端日志').replace(payload['token'], '[REDACTED]')[-12000:], flush=True)
    except Exception:
        print('无法读取后端日志，请使用面板“查看后端日志”重试。', flush=True)


def deploy(payload):
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise ValueError('自动部署需要支持 systemd 的 root Linux 服务器')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if arch not in ASSETS:
        raise ValueError('暂不支持该服务器架构')
    opener = urllib.request.build_opener(NoRedirect())
    url = payload['panel'].rstrip('/') + '/api/v1/server/UniProxy/config?' + urllib.parse.urlencode({'node_id': payload['node_id']})
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + payload['token'], 'Accept': 'application/json'})
    with opener.open(req, timeout=25) as response:
        data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('wp2 节点配置响应过大')
        config = json.loads(data)
    if payload.get('dns_wait') and payload.get('connection_domain'):
        print('验证连接域名 %s → %s' % (payload['connection_domain'], payload['ip']), flush=True)
        wait_node_dns(payload['connection_domain'], payload['ip'], payload.get('ipv6', ''), True)
    protocol, port, cert = node_settings(config, payload['ip'], payload.get('ipv6', ''), payload.get('dns_wait', False))
    print('节点配置验证通过，协议：%s，端口：%s，证书模式：%s' % (protocol, port, cert['cert_mode']), flush=True)
    binding = {'panel': payload['panel'], 'node_id': payload['node_id']}
    marker = ROOT / 'manager-binding.json'
    if (ROOT / 'config.yml').exists():
        if not marker.exists() or json.loads(marker.read_text()) != binding:
            raise ValueError('发现其他节点配置，自动部署不会覆盖；请使用独立实例或先迁移原配置')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    backup_parent = ROOT / 'backups'
    backup_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%d-%H%M%S-'), dir=backup_parent))
    paths = [ROOT / 'config.yml', ROOT / 'manager-binding.json', UNIT,
             BINDIR / 'xboard-node', BINDIR / 'xbctl']
    old = {}
    for i, path in enumerate(paths):
        if path.exists():
            target = backup / str(i)
            shutil.copy2(path, target)
            old[path] = target
    was_active = command('systemctl', 'is-active', 'xboard-node.service', check=False).returncode == 0
    was_enabled = command('systemctl', 'is-enabled', 'xboard-node.service', check=False).returncode == 0
    mutated = False
    try:
        with tempfile.TemporaryDirectory(prefix='xn-deploy-') as temp:
            for name, digest in ASSETS[arch].items():
                download = 'https://github.com/acc66/XboardNode-Plus/releases/download/%s/%s-linux-%s' % (VERSION, name, arch)
                target = Path(temp) / name
                # GitHub release assets intentionally redirect to its CDN.
                with urllib.request.urlopen(download, timeout=120) as response, target.open('wb') as out:
                    shutil.copyfileobj(response, out)
                if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                    raise ValueError('发行文件 SHA256 校验失败：' + name)
                target.chmod(0o755)
            print('下载与校验完成：acc66/XboardNode-Plus ' + VERSION, flush=True)
            mutated = True
            command('systemctl', 'stop', 'xboard-node.service', check=False)
            for name in ASSETS[arch]:
                shutil.copy2(Path(temp) / name, BINDIR / name)
        settings = {'panel': {'url': payload['panel'], 'token': payload['token'], 'node_id': payload['node_id']},
                    'kernel': {'type': 'auto', 'config_dir': str(ROOT)}, 'cert': cert,
                    'log': {'level': 'info'}, 'health_port': 0}
        path = ROOT / 'config.yml'
        path.write_text(json.dumps(settings, ensure_ascii=False, indent=2))
        path.chmod(0o600)
        marker.write_text(json.dumps(binding))
        marker.chmod(0o600)
        UNIT.write_text('''[Unit]
Description=XboardNode-Plus managed node
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=/etc/XboardNode-Plus
Environment=XDG_DATA_HOME=/etc/XboardNode-Plus/data
ExecStart=/usr/local/bin/xboard-node -c /etc/XboardNode-Plus/config.yml
Restart=always
RestartSec=5
LimitNOFILE=1048576
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
''')
        dropin = Path('/etc/systemd/system/xboard-node.service.d')
        if dropin.exists() and any(dropin.iterdir()):
            raise ValueError('存在自定义 systemd 覆盖配置，请先检查，避免错误覆盖')
        if shutil.which('ufw'):
            status = command('ufw', 'status', check=False).stdout
            if 'Status: active' in status:
                if payload.get('open_all_ports', False):
                    command('ufw', 'insert', '1', 'allow', 'in', 'from', 'any', 'to', 'any')
                    command('ufw', 'insert', '1', 'allow', 'out', 'from', 'any', 'to', 'any')
                    print('已按创建设置放行本机 UFW 全部入站/出站端口。', flush=True)
                transport = 'udp' if protocol in ['hysteria', 'hysteria2', 'tuic'] else 'tcp'
                command('ufw', 'allow', '%d/%s' % (port, transport))
                if cert['cert_mode'] == 'http':
                    command('ufw', 'allow', '80/tcp')
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', 'xboard-node.service')
        command('systemctl', 'restart', 'xboard-node.service')
        for attempt in range(180):
            pid_result = command('systemctl', 'show', '-p', 'MainPID', '--value', 'xboard-node.service', check=False)
            healthy = node_listening(pid_result.stdout.strip(), port)
            cert_ok = cert['cert_mode'] == 'none'
            certpath = ROOT / 'certs' / 'cert.pem'
            if not cert_ok and certpath.exists():
                cert_ok = command('openssl', 'x509', '-in', str(certpath), '-noout', '-checkend', '86400', check=False).returncode == 0
            if healthy and cert_ok and command('systemctl', 'is-active', 'xboard-node.service', check=False).returncode == 0:
                if attempt < 3:
                    time.sleep(1)
                    continue
                print('部署验证通过：服务运行、开机自启、节点监听端口正常。', flush=True)
                if cert['cert_mode'] == 'http':
                    print('ACME 证书已签发；内置 CertMagic 自动续期并重新加载，无需另配 cron。', flush=True)
                print('节点客户端仍需能连接此 IP/域名；云防火墙与外部网络连通性不由本机健康检查证明。', flush=True)
                backend_diagnostics(payload, '安装完成')
                return
            time.sleep(1)
        raise ValueError('服务或证书验证超时，请检查 DNS、80 端口、节点端口和 wp2 配置')
    except Exception:
        backend_diagnostics(payload, '部署失败，回滚前')
        if mutated:
            command('systemctl', 'stop', 'xboard-node.service', check=False)
            for path in paths:
                if path in old:
                    shutil.copy2(old[path], path)
                else:
                    path.unlink(missing_ok=True)
            command('systemctl', 'daemon-reload', check=False)
            if was_enabled:
                command('systemctl', 'enable', 'xboard-node.service', check=False)
            else:
                command('systemctl', 'disable', 'xboard-node.service', check=False)
            if was_active:
                command('systemctl', 'start', 'xboard-node.service', check=False)
            print('部署失败，程序、配置与服务状态已尝试恢复。', flush=True)
        raise
