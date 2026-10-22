#!/usr/bin/env python3
"""Apply an operator IP -> response-message list to the running nginx, without restart.

The request path uses native nginx map/return only. A host timer calls this
worker; unchanged lists/container generations require no nginx exec or reload.
"""

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


REVISION = 1
SCANNER_LOG = '/tmp/myscoutee-scanner.log'
SCANNER_THRESHOLD = 100
SCANNER_WINDOW = 600
MAP_PATH = '/etc/nginx/myscoutee-blocked-ips.map'
MAIN_PATH = '/etc/nginx/nginx.conf'
SERVER_PATHS = ('/etc/nginx/conf.d/spring.conf',
                '/etc/nginx/myscoutee-templates/spring.conf')
MAP_MARKER = '# myscoutee-ip-blocklist:map'
SERVER_MARKER = '# myscoutee-ip-blocklist:server'
MAP_BLOCK = '''    # myscoutee-ip-blocklist:map
    map $remote_addr $myscoutee_block_message {
        default "";
        include /etc/nginx/myscoutee-blocked-ips.map;
    }
'''
SERVER_BLOCK = '''    # myscoutee-ip-blocklist:server
    error_page 418 =403 @myscoutee_ip_blocked;
    if ($myscoutee_block_message != "") { return 418; }
    location @myscoutee_ip_blocked {
        default_type text/plain;
        add_header Cache-Control "no-store" always;
        return 403 "$myscoutee_block_message\\n";
    }
'''


def compile_list(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate blocklist address')
            result[key] = value
        return result

    data = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(data, dict) or len(data) > 10000:
        raise ValueError('Blocklist must be an object with at most 10000 IP/message pairs')
    normalized = {}
    for address, message in data.items():
        # Exact source addresses only; never trust X-Forwarded-For or a regex.
        if '%' in address:
            raise ValueError('Scoped addresses are not HTTP client addresses')
        address = ipaddress.ip_address(address).compressed
        if address in normalized:
            raise ValueError('Duplicate normalized blocklist address')
        if (not isinstance(message, str) or not message.strip()
                or len(message.encode('utf-8')) > 1000
                or '$' in message
                or any(ord(c) < 32 or ord(c) == 127 for c in message)):
            raise ValueError('Messages must be single-line text without nginx variables, at most 1000 UTF-8 bytes')
        message = message.replace('\\', '\\\\').replace('"', '\\"')
        normalized[address] = message
    return ''.join(f'"{address}" "{message}";\n'
                   for address, message in sorted(normalized.items())).encode('utf-8')


def add_hooks(main, servers):
    if MAP_MARKER not in main:
        main, count = re.subn(r'(?m)^http\s*\{\s*\n',
                              lambda m: m[0] + MAP_BLOCK, main)
        if count != 1:
            raise ValueError('Expected one nginx http context')
    result = {}
    for path, text in servers.items():
        if SERVER_MARKER not in text:
            text, count = re.subn(r'(?m)^server\s*\{\s*\n',
                                  lambda m: m[0] + SERVER_BLOCK, text)
            if count != 2:
                raise ValueError('Expected the existing HTTP and HTTPS server pair')
        elif text.count(SERVER_MARKER) != 2:
            raise ValueError('Incomplete nginx blocklist integration')
        result[path] = text
    return main, result


class Docker:
    def __init__(self, container):
        self.container = container

    def run(self, *args, data=None, check=True):
        return subprocess.run(['docker', *args], input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=check, timeout=30)

    def generation(self):
        result = self.run('inspect', '--format',
                          '{{.Id}} {{.State.StartedAt}} {{.State.Running}}',
                          self.container, check=False)
        if result.returncode:
            return None
        value = result.stdout.decode().strip()
        return value if value.endswith(' true') else None

    def read(self, path, optional=False):
        result = self.run('exec', self.container, 'cat', path, check=False)
        if result.returncode:
            if optional:
                exists = self.run('exec', self.container, 'test', '-e', path, check=False)
                if exists.returncode == 1:
                    return None
            raise RuntimeError('Cannot read nginx configuration: ' + path)
        return result.stdout

    def write(self, path, value):
        if value is None:
            self.run('exec', self.container, 'rm', '-f', path)
        else:
            # Fixed paths and positional arguments: no message enters shell code.
            self.run('exec', '-i', self.container, 'sh', '-c',
                     'umask 022; cat > "$1.blocklist-tmp" && mv "$1.blocklist-tmp" "$1"',
                     'sh', path, data=value)

    def validate(self):
        result = self.run('exec', self.container, 'nginx', '-t', check=False)
        if result.returncode:
            raise RuntimeError('nginx -t rejected the blocklist configuration')

    def reload(self):
        self.run('exec', self.container, 'nginx', '-s', 'reload')

    def scanner_lines(self, generation, cursor):
        result = self.run('exec', self.container, 'stat', '-c', '%i %s', SCANNER_LOG, check=False)
        if result.returncode:
            return b'', cursor
        inode, size = map(int, result.stdout.split())
        offset = cursor.get('offset', 0) if cursor.get('generation') == generation and cursor.get('inode') == inode else 0
        if size < offset:
            offset = 0
        if size == offset:
            return b'', cursor
        # Read a bounded complete-line batch; never execute paths/messages from logs.
        data = self.run('exec', self.container, 'sh', '-c',
                        'tail -c +"$1" "$2" | head -c 4194304',
                        'sh', str(offset + 1), SCANNER_LOG).stdout
        end = data.rfind(b'\n') + 1
        return data[:end], {'generation': generation, 'inode': inode, 'offset': offset + end}


def save_json(path, value):
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.write('\n')
    tmp.replace(path)


def detect_scanners(docker, state_dir, now=None):
    """100 unknown paths in ten minutes -> durable ban, using nginx's own log.

    The generated findings are kept separate from the operator-edited list.
    Removing a generated entry unblocks it without changing manual entries.
    """
    now = time.time() if now is None else now
    state_path, bans_path = state_dir / 'scanner-state.json', state_dir / 'scanner-blocked-ips.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {'cursor': {}, 'ips': {}}
    bans = json.loads(bans_path.read_text()) if bans_path.exists() else {}
    # Validate durable data before merging it into native nginx configuration.
    compile_list(json.dumps({address: evidence['message'] for address, evidence in bans.items()}))
    generation = docker.generation()
    if generation is None:
        return {address: evidence['message'] for address, evidence in bans.items()}
    data, cursor = docker.scanner_lines(generation, state.get('cursor', {}))
    if not data:
        return {address: evidence['message'] for address, evidence in bans.items()}
    ips = state.get('ips', {})
    ips = {ip: record for ip, record in ips.items() if record['times'] and record['times'][-1] >= now - SCANNER_WINDOW}
    changed_bans = False
    for line in data.splitlines():
        try:
            row = json.loads(line)
            address = ipaddress.ip_address(row['ip']).compressed
            stamp = float(row['time'])
            if address in bans or not now - SCANNER_WINDOW <= stamp <= now + 5:
                continue
            # Health probes and local verification must never become source bans.
            if ipaddress.ip_address(address).is_loopback:
                continue
            path = row['path']
            if not isinstance(path, str) or not path.startswith('/'):
                continue
        except (ValueError, KeyError, TypeError):
            continue
        record = ips.setdefault(address, {'times': [], 'paths': []})
        record['times'] = [value for value in record['times'] if stamp - SCANNER_WINDOW <= value]
        record['times'].append(stamp)
        sample = ''.join(c for c in path[:200] if 32 <= ord(c) < 127)
        if sample not in record['paths'] and len(record['paths']) < 10:
            record['paths'].append(sample)
        if len(record['times']) >= SCANNER_THRESHOLD:
            bans[address] = {'message': 'We see your scanning activity. Access denied.',
                             'detectedAt': stamp, 'requestCount': len(record['times']),
                             'windowSeconds': SCANNER_WINDOW, 'paths': record['paths']}
            del ips[address]
            changed_bans = True
    # Bound uncompleted scanner candidates as well as each read batch.
    if len(ips) > 10000:
        ips = dict(sorted(ips.items(), key=lambda pair: pair[1]['times'][-1], reverse=True)[:10000])
    # Commit bans first: a crash before cursor persistence can replay harmlessly.
    if changed_bans:
        save_json(bans_path, bans)
    save_json(state_path, {'cursor': cursor, 'ips': ips})
    return {address: evidence['message'] for address, evidence in bans.items()}


def apply(docker, compiled, state_dir):
    generation = docker.generation()
    if generation is None:
        return 'nginx not running; list retained'
    fingerprint = hashlib.sha256(str(REVISION).encode() + compiled).hexdigest()
    state_path = state_dir / 'state.json'
    expected = {'generation': generation, 'fingerprint': fingerprint}
    if state_path.exists() and json.loads(state_path.read_text()) == expected:
        return 'unchanged'

    before = {MAIN_PATH: docker.read(MAIN_PATH)}
    before.update({path: docker.read(path) for path in SERVER_PATHS})
    before[MAP_PATH] = docker.read(MAP_PATH, optional=True)
    main, servers = add_hooks(before[MAIN_PATH].decode(),
                              {p: before[p].decode() for p in SERVER_PATHS})
    after = {MAIN_PATH: main.encode(), MAP_PATH: compiled,
             **{p: text.encode() for p, text in servers.items()}}
    changed = [path for path in after if before[path] != after[path]]
    if changed:
        # Keep the original configuration once per container/start generation.
        backup = state_dir / 'backups' / hashlib.sha256(generation.encode()).hexdigest()[:16]
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path, value in before.items():
            saved = backup / path.lstrip('/')
            if value is not None and not saved.exists():
                saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                saved.write_bytes(value)
        written = []
        try:
            for path in changed:
                written.append(path)
                docker.write(path, after[path])
            docker.validate()
            # A deployment owns its own restart; never write a state for a
            # replacement container that did not receive these exact files.
            if docker.generation() != generation:
                raise RuntimeError('nginx container changed while applying blocklist')
            docker.reload()
        except Exception:
            if docker.generation() == generation:
                for path in reversed(written):
                    docker.write(path, before[path])
            raise
    tmp = state_path.with_suffix('.tmp')
    tmp.write_text(json.dumps(expected) + '\n')
    tmp.replace(state_path)
    return 'applied; graceful reload' if changed else 'configuration already current'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', type=Path, default=Path('/etc/myscoutee/nginx-blocked-ips.json'))
    parser.add_argument('--state-dir', type=Path, default=Path('/var/lib/myscoutee/nginx-blocklist'))
    parser.add_argument('--container', default='nginx')
    parser.add_argument('--deployment-lock', type=Path,
                        default=Path('/etc/myscoutee/myscoutee.env.partial-image.lock'))
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    compiled = compile_list(args.list.read_text())
    if args.validate_only:
        print('Blocklist valid')
        return
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.container):
        raise ValueError('Invalid container name')
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with ExitStack() as stack:
        lock = stack.enter_context((args.state_dir / 'worker.lock').open('a'))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        # Reuse the deployment owner's lock when present, without modifying it.
        deployment_lock = args.deployment_lock
        if deployment_lock.exists():
            lock = stack.enter_context(deployment_lock.open('r'))
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print('Deployment in progress; blocklist update deferred')
                return
        docker = Docker(args.container)
        generated = detect_scanners(docker, args.state_dir)
        # Manual policy takes precedence over automatically discovered messages.
        generated.update(json.loads(args.list.read_text()))
        compiled = compile_list(json.dumps(generated))
        result = apply(docker, compiled, args.state_dir)
        if result != 'unchanged':
            print(result)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        # Do not echo arbitrary operator messages or Docker/config contents.
        print(f'Blocklist update failed ({type(error).__name__}); existing workers retained', file=sys.stderr)
        sys.exit(1)
