#!/usr/bin/env python3
"""Native Kubernetes status reader against a local TLS EndpointSlice fixture."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

IMAGE=os.environ.get('NGINX_NATIVE_TEST_IMAGE','myscoutee-nginx:native-edge-test')
def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
def eventually(fn,seconds=12):
    stop=time.monotonic()+seconds
    while time.monotonic()<stop:
        try:
            value=fn()
            if value:return value
        except OSError:pass
        time.sleep(.1)
    raise AssertionError('native Kubernetes state did not converge')
with tempfile.TemporaryDirectory(prefix='myscoutee-kube-') as directory:
    w=Path(directory);w.chmod(0o755)
    run('openssl','req','-x509','-nodes','-newkey','rsa:2048','-keyout',str(w/'key.pem'),
        '-out',str(w/'ca.crt'),'-days','1','-subj','/CN=kubernetes.default.svc',
        '-addext','subjectAltName=DNS:kubernetes.default.svc')
    (w/'token').write_text('fixture-token')
    (w/'nginx.conf').write_text('''include /etc/nginx/myscoutee/modules-main.conf;
user nginx;
worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {worker_connections 1024;}
http {
 access_log off;
 myscoutee_edge_state 32m;
 map $uri $myscoutee_route_known {default 1;}
 server {listen 8080;location = /api/runtime-status {myscoutee_runtime_status;}}
 server {
  listen 443 ssl;
  ssl_certificate /fixture/ca.crt;
  ssl_certificate_key /fixture/key.pem;
  location = /apis/discovery.k8s.io/v1/namespaces/test/endpointslices {
   if ($http_authorization != "Bearer fixture-token") {return 401;}
   default_type application/json;
   alias /fixture/endpoints.json;
  }
 }
}
''')
    def slices(media=True,terminating=False,continuation=''):
        (w/'endpoints.json').write_text(json.dumps({'metadata':{'resourceVersion':'1','continue':continuation},'items':[
            {'metadata':{'labels':{'kubernetes.io/service-name':name}},'endpoints':[{'conditions':{'ready':ready,'terminating':terminating if name=='media' else False}}]}
            for name,ready in [('identity',True),('media',media)]]}))
    slices();name=f'myscoutee-kube-test-{os.getpid()}'
    try:
        run('docker','run','-d','--name',name,'--cpus=1','--memory=128m','--add-host','kubernetes.default.svc:127.0.0.1',
            '-p','127.0.0.1::8080','-v',str(w)+':/fixture:ro',
            '-v',str(w)+':/var/run/secrets/kubernetes.io/serviceaccount:ro',
            '-e','POD_NAMESPACE=test','-e','MYSCOUTEE_RUNTIME_SERVICES=identity,media',
            '--entrypoint','nginx',IMAGE,'-c','/fixture/nginx.conf','-g','daemon off;')
        port=int(run('docker','port',name,'8080/tcp').rsplit(':',1)[1])
        def status():
            c=http.client.HTTPConnection('127.0.0.1',port,timeout=2);c.request('GET','/api/runtime-status');r=c.getresponse();value=json.loads(r.read());c.close();return value
        eventually(lambda:status()['ready'])
        slices(terminating=True);eventually(lambda:status()['known'] and not status()['ready'])
        slices(media=None);eventually(lambda:status()['known'] and not status()['ready'])
        slices();eventually(lambda:status()['ready'])
        slices(continuation='next-page');eventually(lambda:not status()['known'])
        assert '[alert]' not in run('docker','logs',name)
        print(json.dumps({'nativeKubernetes':'pass','tlsAndToken':'pass','readyAndTerminating':'pass','incompleteSnapshot':'pass'}))
    except BaseException:
        print(run('docker','logs',name));raise
    finally:subprocess.run(['docker','rm','-f',name],capture_output=True)
