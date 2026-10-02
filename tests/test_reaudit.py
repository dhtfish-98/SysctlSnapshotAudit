import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from sysctl_snapshot_audit import analyze
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,exit_code):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','sysctl_snapshot_audit',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,exit_code,r.stderr);self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_native_physical_lines_and_full_value(self):
        for value in ('\\\n2','2 # security','2 ; security','2\u20282','2\u0085'):
            s=self.good();s['files']['/etc/sysctl.d/99-policy.conf']=s['files']['/etc/sysctl.d/99-policy.conf'].replace('kernel.kptr_restrict=2','kernel.kptr_restrict='+value)
            with self.subTest(value=value):
                self.assertEqual(analyze(s)['status'],'OPEN');self.assertEqual(self.cli(s,3)['status'],'OPEN')
    def test_plain_assignments_and_full_line_comment_still_pass(self):
        s=self.good();s['files']['/etc/sysctl.d/99-policy.conf']='# entirely ignored comment\n'+s['files']['/etc/sysctl.d/99-policy.conf']+'\n'
        self.assertEqual(analyze(s)['status'],'PASS');self.assertEqual(self.cli(s,0)['status'],'PASS')
