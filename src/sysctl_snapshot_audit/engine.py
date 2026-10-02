"""Resolve explicit sysctl.d snapshots and compare declared workstation policy."""
import fnmatch
import posixpath
import re
from .common import InputError, Report, filemap, logical_lines, mapping

POLICY = {'kernel.randomize_va_space':(2,), 'kernel.kptr_restrict':(2,), 'kernel.dmesg_restrict':(1,),
 'kernel.yama.ptrace_scope':(1,2,3), 'kernel.unprivileged_bpf_disabled':(1,2), 'kernel.perf_event_paranoid':(2,3,4),
 'fs.protected_hardlinks':(1,), 'fs.protected_symlinks':(1,), 'fs.protected_fifos':(2,), 'fs.protected_regular':(2,),
 'fs.suid_dumpable':(0,), 'net.ipv4.ip_forward':(0,), 'net.ipv4.tcp_syncookies':(1,),
 'net.ipv4.conf.all.accept_redirects':(0,), 'net.ipv4.conf.default.accept_redirects':(0,),
 'net.ipv4.conf.all.send_redirects':(0,), 'net.ipv4.conf.default.send_redirects':(0,),
 'net.ipv4.conf.all.accept_source_route':(0,), 'net.ipv4.conf.default.accept_source_route':(0,),
 'net.ipv4.conf.all.rp_filter':(1,2), 'net.ipv4.conf.default.rp_filter':(1,2),
 'net.ipv6.conf.all.accept_redirects':(0,), 'net.ipv6.conf.default.accept_redirects':(0,),
 'net.ipv6.conf.all.accept_source_route':(-1,), 'net.ipv6.conf.default.accept_source_route':(-1,),
 'net.ipv6.conf.all.forwarding':(0,)}
PRIORITY = ('/etc/sysctl.d','/run/sysctl.d','/usr/local/lib/sysctl.d','/usr/lib/sysctl.d','/lib/sysctl.d')
LIMITS=['Policy is an explicit non-routing workstation baseline, not an official kernel recommendation or full Linux security benchmark.',
        'Snapshot observes one point in time. Missing values are OPEN. No sysctl writes, device access, boot-state or host security guarantee.',
        'Only dot-separated keys are interpreted; slash notation, glob assignments and dash-prefixed exclusions are OPEN. Effective per-interface combined kernel settings need runtime review.']

def number(value, label):
    if type(value) is int and -(2**63) <= value < 2**63: return value
    if isinstance(value,str) and len(value.strip()) <= 20 and re.fullmatch(r'-?[0-9]+',value.strip()):
        result=int(value)
        if -(2**63) <= result < 2**63: return result
    raise InputError(label+' requires an integer observation')

def analyze(snapshot):
    mapping(snapshot,'snapshot'); files=filemap(snapshot.get('files',{})); observed=mapping(snapshot.get('observed',{}),'observed')
    report=Report('SysctlSnapshotAudit','26-key non-routing workstation policy, selected sysctl.d precedence and observed drift')
    chosen={}; assignment={}
    for path,text in files.items():
        directory=posixpath.dirname(path); name=posixpath.basename(path)
        if directory not in PRIORITY or not name.endswith('.conf'):
            report.add('file_scope','OPEN',path,'Outside documented sysctl.d search paths');continue
        if name not in chosen or PRIORITY.index(directory)<PRIORITY.index(posixpath.dirname(chosen[name])):chosen[name]=path
    for name,path in sorted(chosen.items()):
        for line,raw in logical_lines(files[path]):
            raw=raw.strip()
            if not raw or raw.startswith(('#',';')):continue
            where=path+':'+str(line)
            match=re.fullmatch(r'(-?[^=\s]+)\s*=\s*([^#;]+?)\s*(?:[#;].*)?',raw)
            if not match:
                report.add('syntax','OPEN',where,'Unknown/exclusion/malformed sysctl directive');continue
            key,value=match.groups();key=key.lstrip('-')
            if '/' in key or any(c in key for c in '*?['):
                report.add('key_semantics','OPEN',where,'Slash/glob key not interpreted');continue
            try:value=number(value,key)
            except InputError:
                report.add('key_value','OPEN',where,'Non-integer value outside audit scope');continue
            assignment[key]=(value,where)
    if not files:report.add('persistent_coverage','OPEN','files','No persistent sysctl.d configuration supplied')
    for key,allowed in POLICY.items():
        if key in assignment:report.check('persistent_policy',assignment[key][0] in allowed,assignment[key][1],key+' expected '+repr(allowed))
        else:report.add('persistent_policy','OPEN',key,'No explicit persistent policy assignment')
        if key in observed:
            value=number(observed[key],key);report.check('observed_policy',value in allowed,key,'Observed '+str(value)+' expected '+repr(allowed))
            if key in assignment:report.check('drift',value==assignment[key][0],key,'Observed vs selected persistent assignment')
        else:report.add('observed_policy','OPEN',key,'No observation; unavailable kernel features are not assumed enabled')
    return report.finish(LIMITS)
