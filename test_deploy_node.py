import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import deploy_node as d


class DeployTests(unittest.TestCase):
    def test_tls_domain_and_dns(self):
        config = {'server_type': 'hysteria2', 'server_port': 443, 'server_name': 'node.example.com'}
        addresses = [(2, 1, 6, '', ('192.0.2.1', 80))]
        with patch.object(d.socket, 'getaddrinfo', return_value=addresses):
            protocol, port, cert = d.node_settings(config, '192.0.2.1')
            self.assertEqual((protocol, port, cert['cert_mode']), ('hysteria2', 443, 'http'))
            self.assertTrue(cert['auto_tls'])
            self.assertEqual(cert['domain'], 'node.example.com')
        with patch.object(d.socket, 'getaddrinfo', return_value=addresses + [(10, 1, 6, '', ('2001:db8::2', 80))]):
            with self.assertRaisesRegex(ValueError, 'DNS'):
                d.node_settings(config, '192.0.2.1')
        with self.assertRaisesRegex(ValueError, '域名'):
            d.node_settings({**config, 'server_name': '192.0.2.1'}, '192.0.2.1')
        protocol, _, cert = d.node_settings({'server_type': 'vless', 'server_port': 443, 'tls': 2}, '192.0.2.1')
        self.assertEqual((protocol, cert['cert_mode']), ('vless', 'none'))
        # The connection address takes precedence over a CDN/SNI host, as in hy8.sh.
        config['server_addr'] = 'node.example.com'
        config['server_name'] = 'cdn.example.net'
        with patch.object(d.socket, 'getaddrinfo', return_value=addresses):
            protocol, _, cert = d.node_settings(config, '192.0.2.1')
        self.assertEqual(cert['domain'], 'node.example.com')

    def test_hysteria2_port_hopping_and_vless_guard(self):
        self.assertEqual(d.parse_port_hops('12000-13000,31000', 'hysteria2', 443), [(12000, 13000), (31000, 31000)])
        with self.assertRaisesRegex(ValueError, '范围无效'):
            d.parse_port_hops('10000-no', 'hysteria2', 443)
        self.assertTrue(d.enable_vless_guard({'network': 'ws', 'tls': 0}, 'vless', {'cert_mode': 'none'}))
        self.assertFalse(d.enable_vless_guard({'network': 'ws', 'tls': 1}, 'vless', {'cert_mode': 'http'}))
        self.assertFalse(d.enable_vless_guard({'network': 'tcp', 'tls': 0}, 'vless', {'cert_mode': 'none'}))
        self.assertEqual(d.release_assets('vless', 'amd64')[0], 'acc66/vless-ban')
        self.assertEqual(d.release_assets('hysteria2', 'amd64')[0], 'acc66/XboardNode-Plus')

    def test_missing_iptables_is_installed_with_detected_package_manager(self):
        calls = []
        installed = {'iptables': False}
        def which(name):
            if name == 'iptables':
                return '/usr/sbin/iptables' if installed['iptables'] else None
            return '/usr/bin/apt-get' if name == 'apt-get' else None
        def run(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('apt-get', 'install'):
                installed['iptables'] = True
            return subprocess.CompletedProcess(args, 0, stdout='')
        with patch.object(d.shutil, 'which', side_effect=which), patch.object(d, 'command', side_effect=run):
            d.ensure_iptables()
        self.assertEqual(calls, [('apt-get', 'update'), ('apt-get', 'install', '-y', 'iptables')])

    def test_missing_iptables_without_package_manager_has_actionable_error(self):
        with patch.object(d.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(ValueError, '请安装 iptables 后重试'):
                d.ensure_iptables()

    def run_deployment(self, root, fail_listener=False, open_all=False, ufw=False, node_ids=None, config=None):
        files = Path(root)
        bindir = files / 'bin'
        bindir.mkdir(exist_ok=True)
        unit = files / 'node.service'
        node_root = files / 'config'
        content = b'mock-release-binary'
        assets = {'amd64': {name: hashlib.sha256(content).hexdigest() for name in ['xboard-node', 'xbctl']}}
        payload = {'panel': 'https://wp2.example', 'token': 'private-token', 'node_ids': node_ids or [929], 'ip': '192.0.2.1', 'open_all_ports': open_all}
        commands = []
        def command(*args, check=True):
            commands.append(args)
            output = '123' if 'MainPID' in str(args) else ('Status: active' if args == ('ufw', 'status') else '')
            return subprocess.CompletedProcess(args, 0, stdout=output)
        config = config or {'server_type': 'shadowsocks', 'server_port': 10001}
        opener = unittest.mock.Mock()
        opener.open.return_value = io.BytesIO(json.dumps(config).encode())
        original_is_dir = Path.is_dir
        def is_dir(path):
            return True if str(path) == '/run/systemd/system' else original_is_dir(path)
        with patch.object(d, 'ROOT', node_root), patch.object(d, 'UNIT', unit), patch.object(d, 'BINDIR', bindir), patch.object(d, 'ASSETS', assets), \
             patch.object(d.os, 'geteuid', return_value=0), patch.object(d.platform, 'machine', return_value='x86_64'), \
             patch.object(Path, 'is_dir', is_dir), patch.object(d.urllib.request, 'build_opener', return_value=opener), \
             patch.object(d.urllib.request, 'urlopen', side_effect=lambda *a, **kw: io.BytesIO(content)), \
             patch.object(d, 'command', side_effect=command), patch.object(d, 'node_listening', return_value=not fail_listener), \
             patch.object(d.time, 'sleep'), patch.object(d.shutil, 'which', side_effect=lambda name: '/usr/sbin/ufw' if name == 'ufw' and ufw else ('/usr/sbin/iptables' if name == 'iptables' else None)), \
             patch.object(d, 'PORT_HOP_SCRIPT', files / 'sbin' / 'xboard-node-port-hops'), \
             patch.object(d, 'PORT_HOP_UNIT', files / 'systemd' / 'xboard-node-port-hops.service'), \
             patch.object(d.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('192.0.2.1', 80))]):
            if fail_listener:
                with self.assertRaisesRegex(ValueError, '超时'):
                    d.deploy(payload)
            else:
                d.deploy(payload)
        return node_root, bindir, unit, commands

    def test_deploy_and_rollback_without_network_or_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, bindir, unit, commands = self.run_deployment(tmp)
            config = root / 'config.yml'
            installed = json.loads(config.read_text())
            self.assertEqual([x['panel']['node_id'] for x in installed['instances']], [929])
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertIn('Restart=always', unit.read_text())
            self.assertTrue(any(args[:2] == ('systemctl', 'enable') for args in commands))
            self.run_deployment(tmp, node_ids=[930])
            installed = json.loads(config.read_text())
            self.assertEqual({x['panel']['node_id'] for x in installed['instances']}, {929, 930})
            original_config = config.read_bytes()
            original_binary = (bindir / 'xboard-node').read_bytes()
            self.run_deployment(tmp, fail_listener=True, node_ids=[929])
            self.assertEqual(config.read_bytes(), original_config)
            self.assertEqual((bindir / 'xboard-node').read_bytes(), original_binary)

    def test_all_ports_only_when_enabled(self):
        for enabled in [False, True]:
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temp:
                _, _, _, commands = self.run_deployment(temp, open_all=enabled, ufw=True)
                rule = ('ufw', 'insert', '1', 'allow', 'in', 'from', 'any', 'to', 'any')
                self.assertEqual(rule in commands, enabled)

    def test_dns_wait_after_update(self):
        config = {'server_type': 'hysteria2', 'server_port': 443, 'server_name': 'node.example.com'}
        wrong = [(2, 1, 6, '', ('192.0.2.2', 80))]
        correct = [(2, 1, 6, '', ('192.0.2.1', 80))]
        with patch.object(d.socket, 'getaddrinfo', side_effect=[wrong, correct]), patch.object(d.time, 'sleep') as sleep:
            _, _, cert = d.node_settings(config, '192.0.2.1', wait_dns=True)
            self.assertEqual(cert['cert_mode'], 'http')
            sleep.assert_called_once_with(10)

    def test_hysteria2_install_creates_persistent_udp_hops(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {'server_type': 'hysteria2', 'server_port': 443, 'server_addr': 'node.example.com', 'ports': '12000-13000,31000'}
            with patch.object(d, 'node_settings', return_value=('hysteria2', 443, {'cert_mode': 'none'})):
                root, _, _, commands = self.run_deployment(tmp, ufw=True, config=config)
            script = Path(tmp) / 'sbin' / 'xboard-node-port-hops'
            unit = Path(tmp) / 'systemd' / 'xboard-node-port-hops.service'
            self.assertTrue(script.exists())
            self.assertIn('--dport 12000:13000 -j REDIRECT --to-ports 443', script.read_text())
            self.assertIn('Before=xboard-node.service', unit.read_text())
            self.assertTrue(any('12000:13000/udp' in args for args in commands))
            self.assertTrue(any(args[:3] == ('systemctl', 'enable', '--now') and args[-1] == 'xboard-node-port-hops.service' for args in commands))


if __name__ == '__main__':
    unittest.main()
