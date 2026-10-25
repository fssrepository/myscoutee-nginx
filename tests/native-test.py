#!/usr/bin/env python3
"""Exercise the real native nginx module and compare constant/geometry load.

No application backend or database is needed. All containers and files are
disposable. PARTITIONS_FILE optionally selects the application's full seed.
"""
import asyncio
import http.client
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

IMAGE = os.environ.get('NGINX_NATIVE_TEST_IMAGE', 'myscoutee-nginx:native-partition-test')
FIXTURE = [
    {'partitionKey': 'outer', 'specificity': 1, 'geometry': {'type': 'Polygon', 'coordinates': [
        [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]],
        [[4, 4], [6, 4], [6, 6], [4, 6], [4, 4]]]}},
    {'partitionKey': 'islands', 'specificity': 2, 'geometry': {'type': 'MultiPolygon', 'coordinates': [
        [[[1, 1], [3, 1], [3, 3], [1, 3], [1, 1]]],
        [[[20, 20], [21, 20], [21, 21], [20, 21], [20, 20]]]]}}]


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()


async def benchmark(port, path, total=64000, concurrency=32):
    samples = []
    async def client():
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        request = f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode()
        for index in range(total // concurrency + 10):
            start = time.perf_counter()
            writer.write(request)
            await writer.drain()
            header = await reader.readuntil(b'\r\n\r\n')
            assert header.split(b'\r\n')[0].endswith(b'200 OK'), header
            size = next(int(line.split(b':', 1)[1]) for line in header.split(b'\r\n')
                        if line.lower().startswith(b'content-length:'))
            await reader.readexactly(size)
            if index >= 10:
                samples.append((time.perf_counter() - start) * 1000)
        writer.close()
        await writer.wait_closed()
    started = time.perf_counter()
    await asyncio.gather(*(client() for _ in range(concurrency)))
    return {'requests': len(samples), 'concurrency': concurrency,
            'requestsPerSecondIncludingWarmup': round((len(samples) + 10*concurrency) / (time.perf_counter()-started)),
            'medianMs': statistics.median(samples), 'p95Ms': sorted(samples)[int(len(samples)*.95)-1]}


with tempfile.TemporaryDirectory(prefix='myscoutee-native-') as directory:
    work = Path(directory)
    # nginx workers need read access to the mounted fixture.
    work.chmod(0o755)
    (work/'countries.json').write_text(json.dumps(FIXTURE))
    (work/'nginx.conf').write_text('''load_module /usr/lib/nginx/modules/ngx_http_partition_module.so;
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  keepalive_requests 10000;
  myscoutee_partition_file /fixture/countries.json;
  server {
    listen 8080;
    location = /api/auth/eligibility { myscoutee_partition_check; add_header Cache-Control "no-store" always; }
    location = /baseline { default_type application/json; return 200 '{"eligible":true,"partitionKey":"country:hu","message":null,"securityGateEnabled":true,"locationRequired":false}\n'; }
  }
}
''')
    with_edge = os.environ.get('WITH_EDGE') == '1'
    if with_edge:
        config = (work/'nginx.conf').read_text()
        config = 'load_module /usr/lib/nginx/modules/ngx_http_edge_module.so;\nthread_pool myscoutee_background threads=1 max_queue=1;\n' + config
        config = config.replace('http {', 'http {\n  myscoutee_edge_state 32m;\n  map $uri $myscoutee_route_known {default 1;}', 1)
        config = config.replace('    listen 8080;', '    listen 8080;\n    myscoutee_public_edge on;\n    if ($myscoutee_block_message != "") {return 403;}')
        config = config.replace('/baseline', '/api/baseline')
        (work/'nginx.conf').write_text(config)
    name = f'myscoutee-native-test-{os.getpid()}'
    try:
        run('docker', 'run', '-d', '--name', name, '--cpus=1', '--memory=128m',
            '-p', '127.0.0.1::8080', '-v', str(work)+':/fixture:ro',
            '--entrypoint', 'nginx', IMAGE, '-c', '/fixture/nginx.conf', '-g', 'daemon off;')
        port = int(run('docker', 'port', name, '8080/tcp').rsplit(':', 1)[1])
        def query(path):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            connection.request('GET', path)
            response = connection.getresponse()
            body = response.read()
            connection.close()
            return response.status, json.loads(body) if response.status == 200 else None
        for attempt in range(40):
            try:
                assert query('/api/baseline' if with_edge else '/baseline')[0] == 200
                break
            except (OSError, AssertionError):
                time.sleep(.1)
        else:
            raise AssertionError(run('docker', 'logs', name))
        for latitude, longitude, key in [(2, 2, 'islands'), (8, 8, 'outer'), (5, 5, None),
                                        (20.5, 20.5, 'islands'), (-8, 8, None)]:
            status, body = query(f'/api/auth/eligibility?latitude={latitude}&longitude={longitude}')
            assert status == 200 and body['partitionKey'] == key and body['eligible'] == bool(key), body
        assert query('/api/auth/eligibility')[1]['locationRequired'] is True
        for params in ['latitude=1', 'latitude=NaN&longitude=1', 'latitude=91&longitude=1',
                       'latitude=1&longitude=181', 'latitude=1%00bad&longitude=1']:
            assert query('/api/auth/eligibility?'+params)[0] == 400, params
        # Hot lookup must survive disappearance of the file: no request-time I/O.
        (work/'countries.json').unlink()
        assert query('/api/auth/eligibility?latitude=2&longitude=2')[1]['partitionKey'] == 'islands'
        full_seed = os.environ.get('PARTITIONS_FILE')
        if full_seed:
            (work/'countries.json').write_bytes(Path(full_seed).read_bytes())
            run('docker', 'exec', name, 'nginx', '-c', '/fixture/nginx.conf', '-t')
            old_workers = run('docker', 'exec', name, 'cat', '/proc/1/task/1/children').split()
            run('docker', 'exec', name, 'nginx', '-c', '/fixture/nginx.conf', '-s', 'reload')
            for attempt in range(80):
                alive = subprocess.run(['docker', 'exec', name, 'sh', '-c',
                    'for pid in "$@"; do test ! -d /proc/"$pid" || exit 1; done', 'sh', *old_workers], capture_output=True)
                if alive.returncode == 0:
                    break
                time.sleep(.025)
            else:
                raise AssertionError('old nginx worker did not drain')
            for latitude, longitude, key in [(52.52, 13.405, 'country:de'), (40.4168, -3.7038, 'country:es'),
                        (28.4636, -16.2518, 'country:es'), (51.5074, -.1278, 'country:gb'),
                        (54.5973, -5.9301, 'country:gb'), (53.3498, -6.2603, None), (48.8566, 2.3522, None)]:
                result = query(f'/api/auth/eligibility?latitude={latitude}&longitude={longitude}')[1]
                assert result['partitionKey'] == key, (latitude, longitude, key, result)
            baseline = asyncio.run(benchmark(port, '/api/baseline' if with_edge else '/baseline'))
            native = asyncio.run(benchmark(port, '/api/auth/eligibility?latitude=47.4979&longitude=19.0402'))
            print(json.dumps({'imageId': run('docker', 'inspect', '--format', '{{.Image}}', name),
                              'edgeModuleEnabled': with_edge, 'cpuLimit': 1, 'memoryLimitMiB': 128, 'fixtureAndCities': 'pass',
                              'baseline': baseline, 'nativeGeometry': native}, indent=2))
        else:
            print('PASS: native Polygon/MultiPolygon, holes, specificity, malformed coordinates and memory-only lookup')
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
