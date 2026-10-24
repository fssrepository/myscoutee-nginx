#!/usr/bin/env python3
"""Exercise the real package's operator-state migration in a temporary directory."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ['APPLICATION_ROOT'])
source=(ROOT/'packaging/debian/postinst').read_text()
function=re.search(r'^ensure_nginx_blocklist\(\) \{.*?^\}',source,re.M|re.S).group()
class Migration(unittest.TestCase):
 def apply(self,directory):
  return subprocess.run(['bash','-c','set -euo pipefail\n'+function+'\nensure_nginx_blocklist'],env={**os.environ,'PACKAGE_ETC':str(directory)},capture_output=True)
 def test_preserves_existing_bytes_and_initializes_empty_only_once(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);legacy=p/'nginx-blocked-ips.json';contents=b'{"192.0.2.1":"We see you"}\n';legacy.write_bytes(contents)
   self.assertEqual(self.apply(p).returncode,0)
   self.assertEqual((p/'nginx/nginx-blocked-ips.json').read_bytes(),contents)
   self.assertFalse(legacy.exists())
   self.assertEqual(self.apply(p).returncode,0)
   self.assertEqual((p/'nginx/nginx-blocked-ips.json').read_bytes(),contents)
 def test_fresh_install_is_empty_and_other_package_secrets_are_separate(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'application.env').write_text('private fixture')
   self.assertEqual(self.apply(p).returncode,0)
   self.assertEqual([v.name for v in (p/'nginx').iterdir()],['nginx-blocked-ips.json'])
   self.assertEqual((p/'nginx/nginx-blocked-ips.json').read_text(),'{}\n')
 def test_rejects_symlink_instead_of_replacing_operator_state(self):
  for name in ['nginx','nginx-blocked-ips.json','nginx/nginx-blocked-ips.json']:
   with tempfile.TemporaryDirectory() as d:
    p=Path(d);target=p/'outside';target.write_text('retain')
    link=p/name;link.parent.mkdir(parents=True,exist_ok=True);link.symlink_to(target)
    self.assertNotEqual(self.apply(p).returncode,0)
    self.assertEqual(target.read_text(),'retain')
if __name__=='__main__':unittest.main()
