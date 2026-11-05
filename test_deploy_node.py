import hashlib
import io
import json
from pathlib import Path
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

    def run_deployment(self, root, fail_listener=False):
        files = Path(root)
        bindir = files / 'bin'
        bindir.mkdir(exist_ok=True)
        unit = files / 'node.service'
        node_root = files / 'config'
        content = b'mock-release-binary'
        assets = {'amd64': {name: hashlib.sha256(content).hexdigest() for name in ['xboard-node', 'xbctl']}}
        payload = {'panel': 'https://wp2.example', 'token': 'private-token', 'node_id': 929, 'ip': '192.0.2.1'}
        commands = []
        def command(*args, check=True):
            commands.append(args)
            output = '123' if 'MainPID' in str(args) else ''
            return subprocess.CompletedProcess(args, 0, stdout=output)
        config = {'server_type': 'shadowsocks', 'server_port': 10001}
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
             patch.object(d.time, 'sleep'), patch.object(d.shutil, 'which', return_value=None):
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
            self.assertEqual(json.loads(config.read_text())['panel']['node_id'], 929)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertIn('Restart=always', unit.read_text())
            self.assertTrue(any(args[:2] == ('systemctl', 'enable') for args in commands))
            original_config = config.read_bytes()
            original_binary = (bindir / 'xboard-node').read_bytes()
            self.run_deployment(tmp, fail_listener=True)
            self.assertEqual(config.read_bytes(), original_config)
            self.assertEqual((bindir / 'xboard-node').read_bytes(), original_binary)


if __name__ == '__main__':
    unittest.main()
