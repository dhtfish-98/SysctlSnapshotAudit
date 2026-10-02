# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import unittest
from sysctl_snapshot_audit import analyze
from sysctl_snapshot_audit.engine import POLICY
from sysctl_snapshot_audit.common import InputError

class SysctlTests(unittest.TestCase):
    def good(self):
        observed={k:v[0] for k,v in POLICY.items()};return dict(files={'/etc/sysctl.d/99-policy.conf':'\n'.join(k+'='+str(v) for k,v in observed.items())},observed=observed)
    def test_complete_positive(self):self.assertEqual(analyze(self.good())['status'],'PASS')
    def test_precedence_basename(self):
        s=self.good();s['files']['/usr/lib/sysctl.d/99-policy.conf']='kernel.kptr_restrict=0';self.assertEqual(analyze(s)['status'],'PASS')
    def test_late_file_override(self):
        s=self.good();s['files']['/etc/sysctl.d/zz-override.conf']='kernel.kptr_restrict=0';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_drift(self):
        s=self.good();s['observed']['kernel.yama.ptrace_scope']=2;r=analyze(s)
        self.assertTrue(any(f['check']=='drift' and f['status']=='FAIL' for f in r['findings']))
    def test_missing_open(self):self.assertEqual(analyze({})['status'],'OPEN')
    def test_unknown_syntax(self):
        s=self.good();s['files']['/etc/sysctl.d/a.conf']='net/ipv4/ip_forward=0';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_glob_open(self):
        s=self.good();s['files']['/etc/sysctl.d/a.conf']='net.ipv4.conf.*.accept_redirects=0';self.assertEqual(analyze(s)['status'],'OPEN')
    def test_bool_is_not_integer(self):
        s=self.good();s['observed']['kernel.kptr_restrict']=True
        with self.assertRaises(InputError):analyze(s)
    def test_noninteger(self):
        s=self.good();s['observed']['kernel.kptr_restrict']='disabled'
        with self.assertRaises(InputError):analyze(s)
    def test_nonobject_files(self):
        with self.assertRaises(InputError):analyze({'files':[]})

    def test_large_integer_text(self):
        snapshot=self.good();snapshot['observed']['kernel.kptr_restrict']='9'*5000
        with self.assertRaises(InputError):analyze(snapshot)
    def test_large_integer_native(self):
        snapshot=self.good();snapshot['observed']['kernel.kptr_restrict']=2**64
        with self.assertRaises(InputError):analyze(snapshot)
    def test_nonascii_integer_config_open(self):
        snapshot=self.good();snapshot['files']['/etc/sysctl.d/99-policy.conf']=snapshot['files']['/etc/sysctl.d/99-policy.conf'].replace('kernel.kptr_restrict=2','kernel.kptr_restrict=\u0662')
        self.assertEqual(analyze(snapshot)['status'],'OPEN')
    def test_nonascii_integer_observation_error(self):
        snapshot=self.good();snapshot['observed']['kernel.kptr_restrict']='\u0662'
        with self.assertRaises(InputError):analyze(snapshot)
