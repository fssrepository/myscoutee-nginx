#!/usr/bin/env python3
"""Real nginx tests: shared workers, hot policy, persistence, SSE, SSI and stats."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

# Public synthetic fixtures are read by a different container UID.
os.umask(0o022)

IMAGE=os.environ.get('NGINX_NATIVE_TEST_IMAGE','myscoutee-nginx:native-edge-test')
ROOT=Path(__file__).resolve().parents[1]

def run(*args):
    return subprocess.check_output(args,stderr=subprocess.STDOUT,text=True).strip()

def eventually(fn,timeout=8):
    deadline=time.monotonic()+timeout
    while True:
        try:
            value=fn()
            if value:return value
        except (OSError,AssertionError,json.JSONDecodeError):pass
        if time.monotonic()>=deadline:raise AssertionError('condition not reached')
        time.sleep(.05)

with tempfile.TemporaryDirectory(prefix='myscoutee-edge-') as directory:
    w=Path(directory);w.chmod(0o755)
    (w/'state').mkdir(mode=0o777);(w/'state').chmod(0o777)
    (w/'operator').mkdir();(w/'operator/nginx-blocked-ips.json').write_text('{}')
    (w/'headers.conf').write_text('add_header X-Test-Policy shared always;\n')
    (w/'routes.map').write_text('"~^/(?:|demo|article|api/auth/session/login|api/landing/content|api/runtime-status|api/runtime-status/events|assets/diagnostics/landing.js|assets/known-missing.png)$" 1;\n')
    (w/'index.html').write_text('''<html><!--# if expr="$myscoutee_landing_debug = 1" --><script src="/assets/diagnostics/landing.js" async></script><!--# endif --></html>''')
    config='''load_module /usr/lib/nginx/modules/ngx_http_edge_module.so;
thread_pool myscoutee_background threads=1 max_queue=1;
worker_processes 2;
user nginx;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {worker_connections 1024;}
http {
 log_format main '$remote_addr $uri $status';
 include /etc/nginx/myscoutee/request-policy-http.conf;
 map $arg_debug $myscoutee_landing_debug {default 0;1 1;}
 set_real_ip_from 127.0.0.1;
 set_real_ip_from 172.16.0.0/12;
 real_ip_header X-Test-IP;
 server {
  listen 8082;
  location /metrics/ {rewrite ^ /metrics break; root /fixture;}
 }
 server {
  listen 8080;
  set_real_ip_from 127.0.0.1;
  set_real_ip_from 172.16.0.0/12;
  real_ip_header X-Test-IP;
  include /etc/nginx/myscoutee/request-policy-server.conf;
  location = /api/runtime-status {myscoutee_runtime_status;}
  location = /api/runtime-status/events {myscoutee_runtime_events;gzip off;}
  location = /api/auth/session/login {default_type application/json;return 200 '{}';}
  location = /api/landing/content {default_type application/json;return 200 '{}';}
  location = /assets/diagnostics/landing.js {alias /usr/share/nginx/diagnostics/landing.js;}
  location = /assets/known-missing.png {root /fixture;try_files $uri =404;}
  location / {root /fixture;ssi on;try_files /index.html =404;}
 }
 include /etc/nginx/myscoutee/runtime-internal.conf;
}
'''
    (w/'nginx.conf').write_text(config)
    name=f'myscoutee-edge-test-{os.getpid()}'
    def start():
        run('docker','run','-d','--name',name,'--cpus=1','--memory=128m',
            '-p','127.0.0.1::8080','-p','127.0.0.1::9081','-p','127.0.0.1::8082',
            '-e','MYSCOUTEE_RUNTIME_STATUS_TOKENS_JSON='+json.dumps({'profilemanagement':'a'*32,'media':'b'*32}),
            '-v',str(w)+':/fixture:ro','-v',str(w/'state')+':/var/lib/nginx/myscoutee',
            '-v',str(w/'operator')+':/etc/nginx/myscoutee-operator:ro',
            '-v',str(w/'routes.map')+':/etc/nginx/public-routes.map:ro',
            '-v',str(w/'headers.conf')+':/etc/nginx/conf.d/https-response-policy.conf:ro',
            '--entrypoint','nginx',IMAGE,'-c','/fixture/nginx.conf','-g','daemon off;')
        return tuple(int(run('docker','port',name,str(port)+'/tcp').rsplit(':',1)[1]) for port in (8080,9081,8082))
    def query(path='/',ip='198.51.100.1',method='GET',body=None,headers=None,internal=False):
        c=http.client.HTTPConnection('127.0.0.1',ports[internal],timeout=5)
        h={'X-Test-IP':ip};h.update(headers or {})
        c.request(method,path,body=body,headers=h);r=c.getresponse();data=r.read();out=(r.status,data,dict(r.getheaders()));c.close();return out
    def push(service,ready=True,instance='one',token=None):
        return query('/internal/runtime-status',method='POST',body=json.dumps({'instance':instance,'ready':ready}),
                     headers={'X-MyScoutee-Service':service,'Authorization':'Bearer '+(token or ('a'*32 if service=='profilemanagement' else 'b'*32))},internal=True)[0]
    try:
        (w/'metrics').write_text('fixture_metric 1\n')
        ports=start();eventually(lambda:query()[0]==200)
        # KVM monitoring and public traffic may have the same NAT address.
        # Successful internal scrapes must never create a public scanner ban.
        monitor='198.51.100.40'
        for i in range(120):assert query('/metrics/identity',ip=monitor,internal=2)[0]==200
        assert query('/',ip=monitor)[0]==200,'internal monitoring banned the public client'
        # Reloading a known page can hit the independent 429 rate limiter,
        # but neither the successful requests nor those 429s are invalid URLs.
        reloader='198.51.100.41'
        statuses=[query('/demo',ip=reloader)[0] for i in range(300)]
        assert set(statuses)=={200,429},set(statuses)
        eventually(lambda:query('/',ip=reloader)[0]==200)
        # Optional browser discovery is a known route even when unsupported.
        # Its expected 404s must not become scanner evidence.
        devtools='198.51.100.42'
        for i in range(120):
            assert query('/.well-known/appspecific/com.chrome.devtools.json',ip=devtools)[0] in (404,429)
        eventually(lambda:query('/',ip=devtools)[0]==200)
        assert query('/.well-known/appspecific/not-devtools.json',ip=devtools)[0] in (404,429)
        assert b'<script' not in query('/')[1]
        assert b'<script' in query('/?debug=1')[1]
        assert query('/assets/diagnostics/landing.js')[0]==200
        assert query('/.env')[0]==404
        assert query('/demo')[0]==200
        assert query('/article')[0]==200
        assert json.loads(query('/api/runtime-status')[1])['ready'] is False
        assert push('profilemanagement',token='x'*32)==401
        assert push('profilemanagement')==204
        assert json.loads(query('/api/runtime-status')[1])['ready'] is False
        assert push('media')==204
        assert json.loads(query('/api/runtime-status')[1])['ready'] is True
        assert push('media',False)==204
        assert json.loads(query('/api/runtime-status')[1])['ready'] is False
        assert push('media',True,instance='two')==204
        assert json.loads(query('/api/runtime-status')[1])['ready'] is True
        # A real streaming response must deliver changes without a separate process.
        c=http.client.HTTPConnection('127.0.0.1',ports[0],timeout=5);c.request('GET','/api/runtime-status/events');r=c.getresponse()
        assert r.status==200
        first=[r.readline(),r.readline(),r.readline()];assert first[0]==b'event: status\n' and b'"ready":true' in first[1],first
        push('media',False,instance='two')
        changed=[r.readline(),r.readline(),r.readline()];assert b'"ready":false' in changed[1],changed;r.close();c.close()
        # Hot operator list: separate messages, invalid update keeps last good state.
        operator=w/'operator/nginx-blocked-ips.json'
        operator.write_text(json.dumps({'198.51.100.2':'First message','2001:db8::2':'IPv6 message'}))
        eventually(lambda:query(ip='198.51.100.2')[0]==403)
        assert b'First message' in query(ip='198.51.100.2')[1]
        assert b'IPv6 message' in query(ip='2001:db8::2')[1]
        operator.write_text('{invalid')
        invalid=subprocess.run(['docker','exec',name,'nginx','-c','/fixture/nginx.conf','-t'],capture_output=True)
        assert invalid.returncode != 0
        time.sleep(1.2);assert query(ip='198.51.100.2')[0]==403
        operator.write_text('{}');eventually(lambda:query(ip='198.51.100.2')[0]==200)
        # Shared across both workers: 99 attempts are not a permanent ban; 100th is.
        scanner='198.51.100.99'
        for i in range(99):assert query('/missing-'+str(i),ip=scanner)[0] in (404,429)
        assert query('/',ip=scanner)[0] in (200,429)
        query('/assets/known-missing.png',ip=scanner)
        assert query('/',ip=scanner)[0]==403
        assert b'We see your scanning activity' in query('/',ip=scanner)[1]
        assert query('/',ip='198.51.100.101')[0]==200,'one banned client blocked another client'
        assert query('/metrics/identity',ip=scanner,internal=2)[0]==200,'client ban affected internal monitoring'
        journal=w/'state/scanner-blocked-ips.json'
        eventually(lambda:journal.exists())
        records=json.loads(run('docker','exec',name,'cat','/var/lib/nginx/myscoutee/scanner-blocked-ips.json'));assert records[0]['ip']==scanner and records[0]['count']==100,records
        assert records[0]['paths']
        # A persisted ban survives SIGKILL, with no graceful-exit flush.
        run('docker','kill','--signal=KILL',name)
        run('docker','start',name)
        ports=tuple(int(run('docker','port',name,str(p)+'/tcp').rsplit(':',1)[1]) for p in (8080,9081,8082))
        eventually(lambda:query(ip=scanner)[0]==403)
        assert query('/',ip='198.51.100.101')[0]==200
        # Attribution + no HTTP follow-up, then a separate campaign visit with activity.
        query('/?utm_source=ig&utm_medium=paid',ip='198.51.100.20')
        query('/api/landing/content',ip='198.51.100.20')
        query('/?utm_source=ig&utm_medium=paid',ip='198.51.100.21')
        query('/demo',ip='198.51.100.21')
        query('/api/auth/session/login',ip='198.51.100.21',method='POST')
        summary=json.loads(run('docker','exec',name,'wget','-qO-','http://127.0.0.1:9081/internal/traffic-summary'))
        meta=summary['sources']['meta_paid'];assert meta['sessions']==2 and meta['noFurtherActivity']==1 and meta['demo']==1 and meta['login']==1,meta
        # Normal stop flushes a just-detected ban without waiting for a timer.
        scanner_on_stop='198.51.100.100'
        for i in range(100):query('/stop-missing-'+str(i),ip=scanner_on_stop)
        run('docker','stop','--time','10',name)
        run('docker','start',name)
        ports=tuple(int(run('docker','port',name,str(p)+'/tcp').rsplit(':',1)[1]) for p in (8080,9081,8082))
        eventually(lambda:query(ip=scanner_on_stop)[0]==403)
        # Container replacement retains a ban without the application or a host worker.
        logs=run('docker','logs',name);assert '[alert]' not in logs,logs
        run('docker','rm','-f',name);ports=start()
        eventually(lambda:query(ip=scanner)[0]==403)
        run('docker','exec',name,'sh','-c',"printf '[]' > /var/lib/nginx/myscoutee/scanner-blocked-ips.json")
        eventually(lambda:query(ip=scanner)[0]==200)
        run('docker','exec',name,'sh','-c',"printf '{invalid' > /var/lib/nginx/myscoutee/scanner-blocked-ips.json")
        invalid=subprocess.run(['docker','exec',name,'nginx','-c','/fixture/nginx.conf','-t'],capture_output=True)
        assert invalid.returncode != 0
        logs=run('docker','logs',name);assert 'alert' not in logs,logs
        processes=run('docker','exec',name,'ps','-o','comm')
        assert 'python' not in processes and 'runtime-status' not in processes,processes
        print(json.dumps({'nativeEdge':'pass','workers':2,'hotPolicy':'pass','scanner100':'pass','persistence':'pass','readinessSse':'pass','ssi':'pass','metaStats':meta}))
    except BaseException:
        print(run('docker','logs',name));raise
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
