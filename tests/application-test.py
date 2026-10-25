import http.client,json,os,re,ssl,subprocess,tempfile,time
from pathlib import Path
image=os.environ.get('APP_IMAGE','myscoutee-nginx:msc127-prod-test')
def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
with tempfile.TemporaryDirectory(prefix='myscoutee-app-') as d:
 w=Path(d);w.chmod(0o755)
 run('openssl','req','-x509','-nodes','-newkey','rsa:2048','-keyout',str(w/'nginx-nopass.key'),'-out',str(w/'nginx.crt'),'-days','1','-subj','/CN=localhost')
 (w/'upstream.conf').write_text('events {} http { server { listen 8080; listen 18082; location / { default_type application/json; return 200 \'{"fixtureBackend":true,"path":"$request_uri","host":"$http_host"}\'; } } }\n')
 name='myscoutee-app-check-'+str(os.getpid())
 network=name+'-network';backend=name+'-backend'
 run('docker','network','create',network)
 try:
  args=['docker','run','-d','--name',name,'--network',network,'--memory=256m','-p','127.0.0.1::80','-p','127.0.0.1::443','-v',d+':/etc/nginx/keys:ro','--tmpfs','/run/myscoutee-runtime-status','-e','MYSCOUTEE_RUNTIME_STATUS_TOKEN_FILE=/run/myscoutee-runtime-status/token']
  run(*args,image)
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
   if path=='/':
    assert body.rstrip().endswith(b'</html>'),('truncated landing HTML',len(body),body[-200:])
    assert b'</body>' in body and re.search(rb'<script[^>]+src="main-[^"]+\.js"',body)
    bootstrap=re.search(rb'<script[^>]+id="myscoutee-runtime-status"[^>]*>(.*?)</script>',body,re.S)
    assert bootstrap is not None,'missing complete runtime status bootstrap'
    assert 'ready' in json.loads(bootstrap[1])
    assert not re.search(rb'<script[^>]+id=[\"\']myscoutee-landing-debug-recorder',body)
  # No backend service name exists yet: static hosting and readiness must still work.
  assert json.loads(get('/api/runtime-status')[1])['ready'] is False
  assert get('/api/auth/demo-users')[0]==502
  fixture_args=['docker','run','-d','--name',backend,'--network',network,'--memory=64m']
  for host in ['profilemanagement','mongodb','mcp','payment-simulator']:fixture_args+=['--network-alias',host]
  run(*fixture_args,'-v',d+':/fixture:ro','--entrypoint','nginx',image,'-c','/fixture/upstream.conf','-g','daemon off;')
  for i in range(150):
   if get('/api/auth/demo-users')[0]==200:break
   time.sleep(.1)
  else:raise AssertionError('API did not recover through runtime DNS without restarting nginx')
  for path,forwarded in [('/api/auth/demo-users?lang=hu','/auth/demo-users?lang=hu'),('/media/public?key=a%2Fb','/media/public?key=a%2Fb'),('/mcp','/mcp'),('/.well-known/oauth-authorization-server','/mcp/oauth/metadata')]:
   result=json.loads(get(path)[1]);assert result['path']==forwarded,(path,result)
   if path.startswith('/.well-known/'):assert result['host']=='profilemanagement:8080',result
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

  run('docker','stop',backend)
  run('docker','restart',name)
  port=int(run('docker','port',name,'443/tcp').rsplit(':',1)[1])
  for i in range(60):
   try:
    if get('/')[0]==200:break
   except OSError:pass
   time.sleep(.1)
  else:raise AssertionError('frontend did not restart with the backend stopped')
  assert json.loads(get('/api/runtime-status')[1])['ready'] is False

  # The deployed monolith must keep its health and other clients available
  # even when the public client's real source address is banned.
  for i in range(110):
   if get('/scanner-missing-'+str(i))[0]==403:break
  else:raise AssertionError('scanner client was not banned')
  assert get('/')[0]==403
  assert run('docker','exec',name,'wget','-qO-','http://127.0.0.1/nginx-health')=='UP'
  assert '<html' in run('docker','exec',name,'wget','--no-check-certificate','-qO-','https://127.0.0.1/')

  logs=run('docker','logs',name);assert '[alert]' not in logs,logs
  ps=run('docker','exec',name,'ps','-o','comm');assert 'python' not in ps and 'runtime-status' not in ps,ps
  print(json.dumps({'applicationImage':image,'independentStartupAndRestart':'pass','runtimeDnsRecovery':'pass','proxyPaths':'pass','nativeAppConfig':'pass','landingDemo':'pass','geoEligibility':'pass','unknownRoutes':'pass','sharedHeaders':'pass','debugOffAndOn':'pass','banKeepsHealthAndOtherClients':'pass'}))
 except BaseException:
  print(run('docker','logs',name));raise
 finally:
  subprocess.run(['docker','rm','-f',name,backend],capture_output=True)
  subprocess.run(['docker','network','rm',network],capture_output=True)
