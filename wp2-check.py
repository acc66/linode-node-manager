"""Run with: docker compose exec -T manager python3 < wp2-check.py"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

base = os.environ.get('WP2_BASE_URL', '').rstrip('/')
key = os.environ.get('WP2_API_TOKEN', '')
if not base.startswith('https://') or not key:
    raise SystemExit('Missing HTTPS WP2_BASE_URL or WP2_API_TOKEN')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(NoRedirect())
for path, extra in [('/mod_mu/func/ping', {}), ('/mod_mu/nodes', {}), ('/mod_mu/nodes', {'view': 'manager'})]:
    print('Checking', base + path, 'view=manager' if extra else '')
    try:
        with opener.open(base + path + '?' + urllib.parse.urlencode({'key': key, **extra}), timeout=20) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                print('Response too large')
                continue
            result = json.loads(body)
            if not isinstance(result, dict):
                print('Unexpected top-level type:', type(result).__name__)
                continue
            data = result.get('data')
            if extra:
                print('Manager view enabled:', result.get('manager_view') is True)
            print('HTTP:', response.status, 'ret:', str(result.get('ret'))[:20], 'data type:', type(data).__name__)
            if isinstance(data, list):
                print('Node count:', len(data))
                print('Node IDs:', [n.get('id') for n in data[:20] if isinstance(n, dict)])
            elif data == 'pong':
                print('Ping authenticated successfully')
            elif isinstance(data, dict):
                print('Data fields:', list(data)[:20])
    except urllib.error.HTTPError as error:
        print('HTTP:', error.code)
    except (ValueError, UnicodeError):
        print('Response is not valid JSON')
    except Exception as error:
        print('Network error:', type(error).__name__)
