"""Executed on the selected node; credentials are supplied through SSH stdin."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

VERSION = 'v1.18'
VLESS_BAN_VERSION = 'v1.0.0'
ASSETS = {
    'amd64': {'xboard-node': 'aa8dbd7a5640a5bc22c52ca6e4b6e403b4bdc0f857773e8d23ee19f1362690ef',
              'xbctl': 'f6a13a1c9e8841ade84b18d27f765e8b8b00fef54a6f7749ad57b56663972526'},
    'arm64': {'xboard-node': '7196c9e2059904c026b4d53bd7964b0aee94f3f1d43c64b29d78b38e84eb4a28',
              'xbctl': '26e3df24bdd97bbd10a4e36a52a45359e935b415c5d548d29bc0ea221892b955'},
}
VLESS_BAN_ASSETS = {
    'amd64': {'xboard-node': 'c380ca3749a1f50840b3af2595bd85017ff8168b30f8aa43c14b074b43071e00',
              'xbctl': 'cca2e3c41dad4ae771af5e355234be3ea38800a3f76ddf3c7290ca933e91cdca'},
    'arm64': {'xboard-node': 'cfa0db152403a256fee221b7e7ffaf0ff4c1bd8e490cd905ceda75eb25db3e88',
              'xbctl': '3174e3b20377f36e1d60c65a0199bfb338290c864f529d4fa7495342f4ecd6f3'},
}
ROOT = Path('/etc/XboardNode-Plus')
UNIT = Path('/etc/systemd/system/xboard-node.service')
BINDIR = Path('/usr/local/bin')
PORT_HOP_SCRIPT = Path('/usr/local/sbin/xboard-node-port-hops')
PORT_HOP_UNIT = Path('/etc/systemd/system/xboard-node-port-hops.service')


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
        # Xboard's server_addr is the client-facing connection domain. server_name
        # can be a CDN/SNI host and must not take precedence for DNS or certificates.
        domain = str(config.get('server_addr') or config.get('domain') or tls_settings.get('server_name') or config.get('server_name') or '').strip().lower()
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


def parse_port_hops(raw, protocol, primary_port):
    if not raw or protocol not in ('hysteria', 'hysteria2'):
        return []
    values = raw if isinstance(raw, list) else str(raw).split(',')
    ranges = []
    for value in values:
        value = str(value).strip()
        if not value:
            continue
        parts = value.split('-', 1)
        if not all(part.isdigit() for part in parts):
            raise ValueError('Hysteria2 端口跳跃范围无效：' + value[:40])
        start, end = int(parts[0]), int(parts[-1])
        if not (1 <= start <= end <= 65535) or start <= primary_port <= end:
            raise ValueError('Hysteria2 端口跳跃范围无效或包含主监听端口')
        ranges.append((start, end))
    return ranges


def enable_vless_guard(config, protocol, cert):
    tls = str(config.get('tls', 0)).lower()
    if protocol != 'vless' or cert.get('cert_mode') != 'none' or tls not in ('', '0', 'none', 'null'):
        return False
    settings = config.get('network_settings') or {}
    network = str(config.get('network') or settings.get('network') or settings.get('type') or '').lower()
    return network in ('ws', 'websocket')


def release_assets(protocol, arch):
    if protocol == 'vless':
        return 'acc66/vless-ban', VLESS_BAN_VERSION, VLESS_BAN_ASSETS[arch]
    return 'acc66/XboardNode-Plus', VERSION, ASSETS[arch]


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


def port_hop_script(rules):
    if not rules:
        return ''
    lines = ['#!/bin/sh', 'set -eu', 'IPTABLES="$(command -v iptables)"',
             '"$IPTABLES" -t nat -N LNM-HY2-HOP 2>/dev/null || true',
             '"$IPTABLES" -t nat -F LNM-HY2-HOP',
             '"$IPTABLES" -t nat -C PREROUTING -j LNM-HY2-HOP 2>/dev/null || "$IPTABLES" -t nat -A PREROUTING -j LNM-HY2-HOP']
    for start, end, target in rules:
        ports = str(start) if start == end else '%d:%d' % (start, end)
        lines.append('"$IPTABLES" -t nat -A LNM-HY2-HOP -p udp --dport %s -j REDIRECT --to-ports %d' % (ports, target))
    return '\n'.join(lines) + '\n'


def merge_existing_port_hops(script_path, new_rules):
    """Keep current node hopping rules when adding another node to the backend."""
    if not script_path.exists():
        return list(new_rules)
    content = script_path.read_text()
    pattern = re.compile(r'--dport (\d+)(?::(\d+))? -j REDIRECT --to-ports (\d+)')
    existing = [(int(start), int(end or start), int(target))
                for start, end, target in pattern.findall(content)]
    if not existing and content.strip():
        raise ValueError('现有 Hysteria2 端口跳跃规则无法识别，未覆盖已有配置')
    for start, end, _ in new_rules:
        for old_start, old_end, _ in existing:
            if start <= old_end and old_start <= end:
                raise ValueError('新增 Hysteria2 跳跃端口与现有规则重叠：%d-%d' % (start, end))
    return existing + list(new_rules)


def ensure_add_nodes_available(previous_entries, panel, prepared):
    existing = {int(entry.get('panel', {}).get('node_id', 0) or 0)
                for entry in previous_entries
                if str(entry.get('panel', {}).get('url', '')).rstrip('/') == panel.rstrip('/')}
    duplicates = sorted(existing.intersection(item['node_id'] for item in prepared))
    if duplicates:
        raise ValueError('这些节点已安装：%s；如需覆盖，请使用“重装所选节点”' % ', '.join(map(str, duplicates)))


def node_config_dir(panel_url, node_id):
    panel_key = hashlib.sha256(panel_url.rstrip('/').lower().encode()).hexdigest()[:12]
    return ROOT / 'nodes' / panel_key / str(node_id)


def remove_port_hop_rules():
    command('iptables', '-t', 'nat', '-D', 'PREROUTING', '-j', 'LNM-HY2-HOP', check=False)
    command('iptables', '-t', 'nat', '-F', 'LNM-HY2-HOP', check=False)
    command('iptables', '-t', 'nat', '-X', 'LNM-HY2-HOP', check=False)


def ensure_iptables():
    """Install the distro's iptables compatibility tool when UDP hopping needs it."""
    if shutil.which('iptables'):
        return
    managers = [
        ('apt-get', ['apt-get', 'update'], ['apt-get', 'install', '-y', 'iptables']),
        ('dnf', None, ['dnf', 'install', '-y', 'iptables']),
        ('yum', None, ['yum', 'install', '-y', 'iptables']),
        ('apk', None, ['apk', 'add', '--no-cache', 'iptables']),
    ]
    selected = next((entry for entry in managers if shutil.which(entry[0])), None)
    if not selected:
        raise ValueError('Hysteria2 需要 UDP 端口跳跃，但系统未安装 iptables，且未检测到 apt/dnf/yum/apk 包管理器；请安装 iptables 后重试')
    name, update, install = selected
    print('系统缺少 iptables，正在使用 %s 自动安装…' % name, flush=True)
    try:
        if update:
            command(*update)
        command(*install)
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, 'stdout', '') or str(exc)
        detail = ' '.join(str(detail).split())[-500:]
        raise ValueError('自动安装 iptables 失败（%s）：%s；请检查软件源/网络后重试' % (name, detail)) from exc
    if not shutil.which('iptables'):
        raise ValueError('系统包管理器已运行，但仍找不到 iptables 命令；请检查该系统的 iptables 包安装结果')
    print('iptables 已安装，继续配置 Hysteria2 UDP 端口跳跃。', flush=True)


def deploy(payload):
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise ValueError('自动部署需要支持 systemd 的 root Linux 服务器')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if arch not in ASSETS:
        raise ValueError('暂不支持该服务器架构')
    node_ids = payload.get('node_ids') or [payload.get('node_id')]
    if not isinstance(node_ids, list) or not 1 <= len(node_ids) <= 20 or any(not isinstance(x, int) or x <= 0 for x in node_ids) or len(set(node_ids)) != len(node_ids):
        raise ValueError('请选择 1 至 20 个不重复的 wp2 节点')
    opener = urllib.request.build_opener(NoRedirect())
    prepared = []
    connection_domains = payload.get('connection_domains') or {}
    for node_id in node_ids:
        url = payload['panel'].rstrip('/') + '/api/v1/server/UniProxy/config?' + urllib.parse.urlencode({'node_id': node_id})
        req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + payload['token'], 'Accept': 'application/json'})
        with opener.open(req, timeout=25) as response:
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError('wp2 节点 #%s 配置响应过大' % node_id)
            config = json.loads(data)
        connection_domain = connection_domains.get(str(node_id), '')
        if payload.get('dns_wait') and connection_domain:
            print('验证节点 #%s 连接域名 %s → %s' % (node_id, connection_domain, payload['ip']), flush=True)
            wait_node_dns(connection_domain, payload['ip'], payload.get('ipv6', ''), True)
        protocol, port, cert = node_settings(config, payload['ip'], payload.get('ipv6', ''), payload.get('dns_wait', False))
        if cert['cert_mode'] == 'http':
            cert['cert_dir'] = str(ROOT / 'certs' / cert['domain'])
        prepared.append({'node_id': node_id, 'protocol': protocol, 'port': port, 'cert': cert,
                         'hops': parse_port_hops(config.get('ports'), protocol, port),
                         'guard': enable_vless_guard(config, protocol, cert), 'config': config})
        print('节点 #%s 配置验证通过，协议：%s，端口：%s，跳跃端口：%s，证书模式：%s' %
              (node_id, protocol, port, config.get('ports') or '无', cert['cert_mode']), flush=True)
    binding = {'panel': payload['panel'], 'node_ids': list(node_ids)}
    marker = ROOT / 'manager-binding.json'
    config_path = ROOT / 'config.yml'
    previous_binding = {}
    old_config = {}
    previous_entries = []
    global_settings = {}
    if config_path.exists():
        if not marker.exists():
            raise ValueError('发现其他节点配置，自动部署不会覆盖；请先迁移或使用独立实例')
        try:
            previous_binding = json.loads(marker.read_text())
            old_config = json.loads(config_path.read_text())
        except Exception as error:
            raise ValueError('现有后端配置无法安全读取，未做修改') from error
        if previous_binding.get('panel') != payload['panel']:
            raise ValueError('当前后端绑定了其他 wp2 面板，自动安装不会覆盖')
        if isinstance(old_config.get('instances'), list):
            previous_entries = old_config['instances']
            global_settings = {k: v for k, v in old_config.items() if k not in ('instances', 'panel', 'cert', 'guard')}
        elif old_config.get('panel'):
            legacy = {'panel': old_config['panel']}
            for key in ('kernel', 'cert', 'log', 'guard', 'dns'):
                if key in old_config:
                    legacy[key] = old_config[key]
            previous_entries = [legacy]
            global_settings = {k: v for k, v in old_config.items() if k not in ('panel', 'cert', 'guard', 'instances')}
        else:
            raise ValueError('现有后端配置不兼容，未做修改')
    else:
        global_settings = {'kernel': {'type': 'auto', 'config_dir': str(ROOT)}, 'log': {'level': 'info'}}

    operation = payload.get('operation') or 'add'
    if operation == 'add':
        ensure_add_nodes_available(previous_entries, payload['panel'], prepared)
    elif operation != 'replace':
        raise ValueError('节点操作方式无效')

    # XboardNode-Plus/vless-ban requires a private kernel config directory per
    # node instance. Older panel versions wrote ROOT for every node, which
    # makes the newer multi-instance layout validator refuse to start.
    for old_entry in previous_entries:
        old_node_id = int(old_entry.get('panel', {}).get('node_id', 0) or 0)
        if old_node_id > 0:
            old_kernel = old_entry.get('kernel')
            if not isinstance(old_kernel, dict):
                old_kernel = {}
                old_entry['kernel'] = old_kernel
            old_kernel['config_dir'] = str(node_config_dir(payload['panel'], old_node_id))

    # Keep existing node bindings and replace only the IDs explicitly selected.
    for item in prepared:
        node_id = item['node_id']
        entry = {'panel': {'url': payload['panel'], 'token': payload['token'], 'node_id': node_id},
                 'kernel': {'type': 'auto', 'config_dir': str(node_config_dir(payload['panel'], node_id))}, 'log': {'level': 'info'}}
        if item['cert']['cert_mode'] != 'none':
            entry['cert'] = item['cert']
        if item['guard']:
            entry['guard'] = {'enabled': True, 'blacklist': str(ROOT / 'blacklist.txt')}
        previous_entries = [old for old in previous_entries
                            if not (str(old.get('panel', {}).get('url', '')).rstrip('/') == payload['panel'].rstrip('/')
                                    and int(old.get('panel', {}).get('node_id', 0) or 0) == node_id)]
        previous_entries.append(entry)
    selected_vless = any(item['protocol'] == 'vless' for item in prepared)
    backend_repository = previous_binding.get('backend_repository') or ('acc66/vless-ban' if selected_vless else 'acc66/XboardNode-Plus')
    if selected_vless:
        backend_repository = 'acc66/vless-ban'
    if backend_repository == 'acc66/vless-ban':
        release_version, release_map = VLESS_BAN_VERSION, VLESS_BAN_ASSETS[arch]
    else:
        backend_repository, release_version, release_map = 'acc66/XboardNode-Plus', VERSION, ASSETS[arch]
    active_node_ids = sorted({int(entry.get('panel', {}).get('node_id', 0)) for entry in previous_entries
                              if int(entry.get('panel', {}).get('node_id', 0) or 0) > 0})
    binding = {'panel': payload['panel'], 'node_ids': active_node_ids, 'backend_repository': backend_repository}
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    backup_parent = ROOT / 'backups'
    backup_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%d-%H%M%S-'), dir=backup_parent))
    paths = [config_path, ROOT / 'manager-binding.json', UNIT, PORT_HOP_SCRIPT, PORT_HOP_UNIT,
             BINDIR / 'xboard-node', BINDIR / 'xbctl']
    old = {}
    for i, path in enumerate(paths):
        if path.exists():
            target = backup / str(i)
            shutil.copy2(path, target)
            old[path] = target
    was_active = command('systemctl', 'is-active', 'xboard-node.service', check=False).returncode == 0
    was_enabled = command('systemctl', 'is-enabled', 'xboard-node.service', check=False).returncode == 0
    was_hop_enabled = command('systemctl', 'is-enabled', 'xboard-node-port-hops.service', check=False).returncode == 0
    mutated = False
    hop_rules = [(start, end, item['port']) for item in prepared for start, end in item['hops']]
    if operation == 'add':
        hop_rules = merge_existing_port_hops(PORT_HOP_SCRIPT, hop_rules)
    if hop_rules:
        ensure_iptables()
    try:
        with tempfile.TemporaryDirectory(prefix='xn-deploy-') as temp:
            for name, digest in release_map.items():
                download = 'https://github.com/%s/releases/download/%s/%s-linux-%s' % (backend_repository, release_version, name, arch)
                target = Path(temp) / name
                # GitHub release assets intentionally redirect to its CDN.
                with urllib.request.urlopen(download, timeout=120) as response, target.open('wb') as out:
                    shutil.copyfileobj(response, out)
                if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                    raise ValueError('发行文件 SHA256 校验失败：' + name)
                target.chmod(0o755)
            print('下载与校验完成：%s %s' % (backend_repository, release_version), flush=True)
            mutated = True
            command('systemctl', 'stop', 'xboard-node.service', check=False)
            for name in release_map:
                shutil.copy2(Path(temp) / name, BINDIR / name)
        settings = dict(global_settings)
        settings.pop('panel', None)
        settings.pop('instances', None)
        settings['kernel'] = settings.get('kernel') or {'type': 'auto', 'config_dir': str(ROOT)}
        settings['log'] = settings.get('log') or {'level': 'info'}
        settings['instances'] = previous_entries
        settings['health_port'] = 0
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
                for item in prepared:
                    transport = 'udp' if item['protocol'] in ['hysteria', 'hysteria2', 'tuic'] else 'tcp'
                    command('ufw', 'allow', '%d/%s' % (item['port'], transport))
                    if item['cert']['cert_mode'] == 'http':
                        command('ufw', 'allow', '80/tcp')
                    for start_port, end_port in item['hops']:
                        port_range = str(start_port) if start_port == end_port else '%d:%d' % (start_port, end_port)
                        command('ufw', 'allow', port_range + '/udp')
        if hop_rules:
            PORT_HOP_SCRIPT.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            PORT_HOP_UNIT.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            PORT_HOP_SCRIPT.write_text(port_hop_script(hop_rules))
            PORT_HOP_SCRIPT.chmod(0o700)
            PORT_HOP_UNIT.write_text('''[Unit]
Description=Restore Linode Node Manager Hysteria2 port hopping rules
Before=xboard-node.service
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xboard-node-port-hops
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
            command('systemctl', 'daemon-reload')
            command('systemctl', 'enable', '--now', 'xboard-node-port-hops.service')
            command(str(PORT_HOP_SCRIPT))
            print('Hysteria2 UDP 端口跳跃规则已设置并启用开机恢复。', flush=True)
        elif (PORT_HOP_UNIT.exists() or PORT_HOP_SCRIPT.exists()) and operation != 'add':
            if not previous_binding:
                raise ValueError('发现非面板管理的端口跳跃服务，自动安装不会覆盖')
            command('systemctl', 'disable', '--now', 'xboard-node-port-hops.service', check=False)
            remove_port_hop_rules()
            PORT_HOP_SCRIPT.unlink(missing_ok=True)
            PORT_HOP_UNIT.unlink(missing_ok=True)
        command('systemctl', 'daemon-reload')
        command('systemctl', 'enable', 'xboard-node.service')
        command('systemctl', 'restart', 'xboard-node.service')
        for attempt in range(180):
            pid_result = command('systemctl', 'show', '-p', 'MainPID', '--value', 'xboard-node.service', check=False)
            healthy = all(node_listening(pid_result.stdout.strip(), item['port']) for item in prepared)
            cert_ok = True
            for item in prepared:
                cert = item['cert']
                if cert['cert_mode'] == 'none':
                    continue
                certpath = Path(cert.get('cert_dir', ROOT / 'certs')) / 'cert.pem'
                if not certpath.exists() or command('openssl', 'x509', '-in', str(certpath), '-noout', '-checkend', '86400', check=False).returncode != 0:
                    cert_ok = False
                    break
            if healthy and cert_ok and command('systemctl', 'is-active', 'xboard-node.service', check=False).returncode == 0:
                if attempt < 3:
                    time.sleep(1)
                    continue
                print('多节点部署验证通过：服务运行、开机自启、所有节点监听端口正常。', flush=True)
                if any(item['cert']['cert_mode'] == 'http' for item in prepared):
                    print('ACME 证书已签发；内置 CertMagic 自动续期并重新加载，无需另配 cron。', flush=True)
                if any(item['guard'] for item in prepared):
                    print('VLESS 非 TLS WebSocket anti-probe 已启用：访问错误 WS 路径将封禁来源 IP。', flush=True)
                print('节点客户端仍需能连接此 IP/域名；云防火墙与外部网络连通性不由本机健康检查证明。', flush=True)
                backend_diagnostics(payload, '安装完成')
                return
            time.sleep(1)
        raise ValueError('服务或证书验证超时，请检查 DNS、80 端口、节点端口和 wp2 配置')
    except Exception:
        backend_diagnostics(payload, '部署失败，回滚前')
        if mutated:
            command('systemctl', 'stop', 'xboard-node.service', check=False)
            command('systemctl', 'disable', '--now', 'xboard-node-port-hops.service', check=False)
            if hop_rules:
                remove_port_hop_rules()
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
            if was_hop_enabled and PORT_HOP_UNIT.exists():
                command('systemctl', 'enable', '--now', 'xboard-node-port-hops.service', check=False)
            print('部署失败，程序、配置与服务状态已尝试恢复。', flush=True)
        raise
