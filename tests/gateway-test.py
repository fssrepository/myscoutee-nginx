#!/usr/bin/env python3
"""Use the real Kubernetes gateway config as non-root with a read-only root FS."""
import http.client,json,os,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(os.environ['APPLICATION_ROOT'])
IMAGE=os.environ.get('APP_IMAGE','myscoutee-nginx:msc127-prod-test')
def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
with tempfile.TemporaryDirectory(prefix='myscoutee-gateway-') as d:
 w=Path(d);w.chmod(0o755)
 config=(ROOT/'microservices/deploy/chart/files/gateway.conf').read_text()
 for key,value in {'CLUSTER_DNS':'127.0.0.1','METRICS_UPSTREAMS':'','PUBLIC_UPSTREAMS':'','PAYMENT_PROVIDER_LOCATIONS':'','MEDIA_SERVICE':'media','NAMESPACE':'test'}.items():config=config.replace('@'+key+'@',value)
 (w/'nginx.conf').write_text(config)
 (w/'runtime-status.conf').write_text('include /etc/nginx/myscoutee/runtime-status.conf;\n')
 (w/'response-policy.conf').write_text('include /etc/nginx/myscoutee/https-response-policy.prod.conf;\n')
 (w/'public-upstream.conf').write_text('return 503;\n')
 name='myscoutee-gateway-test-'+str(os.getpid())
 try:
  run('docker','run','-d','--name',name,'--cpus=1','--memory=128m','--user','101:101','--read-only',
      '--tmpfs','/tmp:mode=1777,size=32m','--tmpfs','/var/lib/nginx/myscoutee:uid=101,gid=101,mode=0700,size=32m',
      '-v',d+':/etc/myscoutee:ro','-p','127.0.0.1::8080','--entrypoint','nginx',IMAGE,'-c','/etc/myscoutee/nginx.conf','-g','daemon off;')
  port=int(run('docker','port',name,'8080/tcp').rsplit(':',1)[1])
  def get(path):
   c=http.client.HTTPConnection('127.0.0.1',port,timeout=2);c.request('GET',path);r=c.getresponse();v=r.status,r.read(),dict(r.getheaders());c.close();return v
  for i in range(60):
   try:
    if get('/')[0]==200:break
   except OSError:pass
   time.sleep(.1)
  else:raise AssertionError(run('docker','logs',name))
  assert get('/')[2]['X-Content-Type-Options']=='nosniff'
  assert get('/assets/diagnostics/landing.js')[0]==200
  result=get('/api/auth/eligibility?latitude=47.4979&longitude=19.0402');assert json.loads(result[1])['partitionKey']=='country:hu',result
  result=get('/api/auth/eligibility?latitude=48.8566&longitude=2.3522');assert json.loads(result[1])['eligible'] is False,result
  assert get('/api/runtime-status')[0]==200
  assert get('/.env')[0]==404
  assert get('/api/nonexistent-controller')[0]==404
  run('docker','exec',name,'nginx','-c','/etc/myscoutee/nginx.conf','-t')
  assert '[alert]' not in run('docker','logs',name)
  print(json.dumps({'gatewayConfig':'pass','readOnlyNonRoot':'pass','geometry':'pass','sharedPolicy':'pass','application':ROOT.name}))
 except BaseException:
  print(run('docker','logs',name));raise
 finally:subprocess.run(['docker','rm','-f',name],capture_output=True)
