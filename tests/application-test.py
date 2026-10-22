import http.client,json,os,re,ssl,subprocess,tempfile,time
from pathlib import Path
image=os.environ.get('APP_IMAGE','myscoutee-nginx:msc127-prod-test')
def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
with tempfile.TemporaryDirectory(prefix='myscoutee-app-') as d:
 w=Path(d);w.chmod(0o755)
 run('openssl','req','-x509','-nodes','-newkey','rsa:2048','-keyout',str(w/'nginx-nopass.key'),'-out',str(w/'nginx.crt'),'-days','1','-subj','/CN=localhost')
 (w/'upstream.conf').write_text('server { listen 8080; location / { default_type application/json; return 200 \'{"fixtureBackend":true}\'; } }\n')
 name='myscoutee-app-check-'+str(os.getpid())
 try:
  args=['docker','run','-d','--name',name,'--cpus=1','--memory=256m','-p','127.0.0.1::80','-p','127.0.0.1::443','-v',d+':/etc/nginx/keys:ro','--tmpfs','/run/myscoutee-runtime-status','-e','MYSCOUTEE_RUNTIME_STATUS_TOKEN_FILE=/run/myscoutee-runtime-status/token']
  for host in ['profilemanagement','mongodb','mcp','payment-simulator']:args+=['--add-host',host+':127.0.0.1']
  run(*args,'--entrypoint','sh',image,'-c','cat /etc/nginx/keys/upstream.conf >> /etc/nginx/myscoutee/runtime-internal.conf; exec /scripts/nginx-production-entrypoint.sh')
  port=int(run('docker','port',name,'443/tcp').rsplit(':',1)[1])
  def get(path):
   c=http.client.HTTPSConnection('127.0.0.1',port,timeout=5,context=ssl._create_unverified_context());c.request('GET',path);r=c.getresponse();v=(r.status,r.read(),dict(r.getheaders()));c.close();return v
  for i in range(60):
   try:
    if get('/nginx-health')[0]==200:break
   except OSError:pass
   time.sleep(.1)
  else:raise AssertionError(run('docker','logs',name))
  for path in ['/','/assets/diagnostics/landing.js']:
   status,body,headers=get(path);assert status==200,(path,status,body[:200]);assert headers['X-Content-Type-Options']=='nosniff'
   if path=='/':assert not re.search(rb'<script[^>]+id=[\"\']myscoutee-landing-debug-recorder',body)
  response=get('/api/auth/eligibility?latitude=47.4979&longitude=19.0402');assert json.loads(response[1])['partitionKey']=='country:hu',response
  response=get('/api/auth/eligibility?latitude=48.8566&longitude=2.3522');assert json.loads(response[1])['eligible'] is False,response
  assert get('/api/auth/demo-users')[0] == 200
  assert get('/.env')[0]==404
  assert get('/api/not-a-real-controller-path')[0]==404
  assert get('/api/runtime-status')[0]==200
  assert get('/__landing-debug?d=a',)[0]==404
  run('docker','exec',name,'nginx','-t')
  old=run('docker','exec',name,'cat','/proc/1/task/1/children').split()
  run('docker','exec',name,'sed','-i','s/map $host $myscoutee_landing_debug { default 0; }/map $host $myscoutee_landing_debug { default 1; }/','/etc/nginx/myscoutee/observability-http.conf')
  run('docker','exec',name,'nginx','-s','reload')
  for i in range(60):
   result=subprocess.run(['docker','exec',name,'sh','-c','for pid in "$@"; do test ! -d /proc/"$pid" || exit 1; done','sh',*old],capture_output=True)
   if result.returncode==0:break
   time.sleep(.05)
  else:raise AssertionError('old workers did not drain')
  assert re.search(rb'<script[^>]+id=[\"\']myscoutee-landing-debug-recorder',get('/')[1])

  logs=run('docker','logs',name);assert '[alert]' not in logs,logs
  ps=run('docker','exec',name,'ps','-o','comm');assert 'python' not in ps and 'runtime-status' not in ps,ps
  print(json.dumps({'applicationImage':image,'nativeAppConfig':'pass','landingDemo':'pass','geoEligibility':'pass','unknownRoutes':'pass','sharedHeaders':'pass','debugOffAndOn':'pass'}))
 except BaseException:
  print(run('docker','logs',name));raise
 finally:subprocess.run(['docker','rm','-f',name],capture_output=True)
