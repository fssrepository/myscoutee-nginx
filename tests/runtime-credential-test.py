#!/usr/bin/env python3
"""Prove the native receiver shares its credential across UIDs despite umask 077."""
import os
from pathlib import Path
import subprocess
import tempfile
import time

image = os.environ.get('NGINX_NATIVE_TEST_IMAGE', 'myscoutee-nginx:native-edge-test')
def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()

with tempfile.TemporaryDirectory(prefix='myscoutee-runtime-credential-') as temporary:
    root = Path(temporary)
    root.chmod(0o755)
    config = root / 'nginx.conf'
    config.write_text('''load_module /usr/lib/nginx/modules/ngx_http_edge_module.so;
thread_pool myscoutee_background threads=1 max_queue=1;
worker_processes 1;
user nginx;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {worker_connections 64;}
http { server { listen 8080; location / { myscoutee_runtime_status; } } }
''')
    config.chmod(0o644)
    for existing in (False, True):
        name = f'myscoutee-runtime-credential-{os.getpid()}'
        script = 'umask 077; '
        if existing:
            script += "printf '%064d' 1 > /runtime/token; chmod 0400 /runtime/token; sha256sum /runtime/token > /runtime/before; "
        script += 'exec nginx -c /fixture/nginx.conf -g "daemon off;"'
        try:
            run('docker', 'run', '-d', '--name', name, '--network', 'none',
                '--tmpfs', '/runtime:mode=0755', '-v', str(root) + ':/fixture:ro',
                '-e', 'MYSCOUTEE_RUNTIME_STATUS_TOKEN_FILE=/runtime/token',
                '--entrypoint', '/bin/sh', image, '-c', script)
            for _ in range(50):
                result = subprocess.run(['docker', 'exec', '--user', '10001:10001', name,
                    'sh', '-c', 'test -r /runtime/token && test ! -w /runtime/token && test "$(stat -c %a /runtime/token)" = 444'],
                    capture_output=True)
                if result.returncode == 0: break
                time.sleep(0.1)
            else:
                state = run('docker', 'inspect', '--format', '{{.State.Status}}', name)
                if state != 'running': raise AssertionError('Nginx did not start: ' + run('docker', 'logs', name))
                mode = run('docker', 'exec', name, 'stat', '-c', '%a', '/runtime/token')
                raise AssertionError('Backend UID cannot read the shared runtime credential; mode=' + mode)
            if existing:
                run('docker', 'exec', name, 'sha256sum', '-c', '/runtime/before')
            print('PASS existing credential preserved' if existing else 'PASS credential created with restrictive umask')
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
