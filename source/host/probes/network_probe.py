#!/usr/bin/env python3
"""Fixed-v3 network attempts. PASS is assigned only by the caller after the exact nft counter delta."""
import json,os,pathlib,socket,subprocess,sys,time
from cgroup_utils import CgroupEvidenceError,locate_process_cgroup

PLAN={
 'dns-stub':('dns',None,'PASS_ON_RESOLUTION'),
 'allow-tcp443':('tcp',None,'connected'),
 'block-tcp80':('tcp',7,'not_connected'),
 'block-udp53':('udp',7,'counter_delta'),
 'block-tcp53':('tcp',7,'not_connected'),
 'block-metadata80':('tcp',2,'not_connected'),
 'block-metadata443':('tcp',2,'not_connected'),
 'block-rfc1918-443':('tcp',4,'not_connected'),
 'child-block-tcp80':('child',7,'not_connected'),
 'ipv6-loopback80':('tcp6',5,'not_connected'),
 'ipv6-linklocal443':('tcp6',3,'not_connected'),
 'ipv6-public80':('tcp6',7,'not_connected'),
 'ipv6-public53-tcp':('tcp6',7,'not_connected'),
 'ipv6-public53-udp':('udp6',7,'counter_delta'),
 'control-ubuntu-tcp80':('control',None,'connected_and_no_table_delta')}
DEST={
 'allow-tcp443':('1.1.1.1',443), 'block-tcp80':('1.1.1.1',80), 'block-udp53':('1.1.1.1',53),
 'block-tcp53':('1.1.1.1',53), 'block-metadata80':('169.254.169.254',80),
 'block-metadata443':('169.254.169.254',443), 'block-rfc1918-443':('10.0.0.1',443),
 'ipv6-loopback80':('::1',80), 'ipv6-public80':('2606:4700:4700::1111',80),
 'ipv6-public53-tcp':('2606:4700:4700::1111',53), 'ipv6-public53-udp':('2606:4700:4700::1111',53),
 'child-block-tcp80':('1.1.1.1',80),
 'control-ubuntu-tcp80':('1.1.1.1',80)}
def _require_armed(test):
 import pwd
 if test=='control-ubuntu-tcp80':
  if os.environ.get('ST01R_CONTROL_ARMED')!='YES' or pwd.getpwuid(os.getuid()).pw_name!='ubuntu': raise CgroupEvidenceError('UBUNTU_CONTROL_NOT_ARMED_OR_WRONG_UID')
 else:
  if os.environ.get('ST01R_RUN_HOST_TESTS')!='1': raise CgroupEvidenceError('NETWORK_TESTS_NOT_ARMED')
  if pwd.getpwuid(os.getuid()).pw_name!='watson-s1': raise CgroupEvidenceError('NETWORK_TEST_WRONG_UID')
  unit=os.environ.get('ST01R_UNIT_NAME','')
  if not unit: raise CgroupEvidenceError('UNIT_NAME_MISSING')
  loc=locate_process_cgroup()
  if not loc['proc_cgroup'].endswith('/'+unit): raise CgroupEvidenceError('NETWORK_PROCESS_CGROUP_MISMATCH')
def _v6_enabled():
 p=pathlib.Path('/proc/sys/net/ipv6/conf/all/disable_ipv6')
 return p.is_file() and p.read_text().strip()=='0'
def _linklocal_index():
 p=pathlib.Path('/proc/net/if_inet6')
 if not p.exists(): return None
 for line in p.read_text().splitlines():
  parts=line.split()
  if len(parts)>=6 and parts[0].lower().startswith('fe80'):
   try: return socket.if_nametoindex(parts[5])
   except OSError: continue
 return None
def _tcp(host,port,family,scope=0):
 s=socket.socket(family,socket.SOCK_STREAM); s.settimeout(2)
 try:
  addr=(host,port,0,scope) if family==socket.AF_INET6 else (host,port)
  s.connect(addr); return True,None
 except OSError as e: return False,type(e).__name__
 finally: s.close()
def _udp(host,port,family,scope=0):
 s=socket.socket(family,socket.SOCK_DGRAM); s.settimeout(1)
 try:
  addr=(host,port,0,scope) if family==socket.AF_INET6 else (host,port)
  s.connect(addr); s.send(b'\x00'); return True,None
 except OSError as e: return False,type(e).__name__
 finally: s.close()
def _child(test):
 host,port=DEST[test]; family=socket.AF_INET6 if ':' in host else socket.AF_INET
 connected,err=_tcp(host,port,family)
 return {'connected':connected,'error_class':err,'attempted':True,'pid':os.getpid()}
def run(test):
 if test not in PLAN: raise ValueError('TEST_NOT_IN_FIXED_V3_PLAN')
 _require_armed(test); proto,rule,expect=PLAN[test]
 if proto=='dns':
  p=subprocess.run(['getent','ahosts','ubuntu.com'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,check=False)
  return {'test':test,'status':'PASS' if p.returncode==0 and bool(p.stdout.strip()) else 'FAIL','exit_code':p.returncode,'resolved_rows':len(p.stdout.splitlines()),'expected_rule':rule}
 if test.startswith('ipv6-') and not _v6_enabled(): return {'test':test,'status':'NOT_TESTABLE','reason':'IPV6_DISABLED','expected_rule':rule}
 if test=='ipv6-linklocal443':
  idx=_linklocal_index()
  if idx is None:return {'test':test,'status':'NOT_TESTABLE','reason':'NO_IPV6_LINKLOCAL_INTERFACE','expected_rule':rule}
  result,err=_tcp('fe80::1',443,socket.AF_INET6,idx)
  return {'test':test,'status':'ATTEMPTED','connected':result,'error_class':err,'interface_index':idx,'expected_rule':rule}
 if proto=='child':
  p=subprocess.run([sys.executable,__file__,'--child',test],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5,check=False)
  if p.returncode: raise RuntimeError('CHILD_NETWORK_TEST_FAILED')
  return {'test':test,'status':'ATTEMPTED','child':json.loads(p.stdout),'expected_rule':rule}
 host,port=DEST[test]
 if proto in ('udp','udp6'):
  sent,err=_udp(host,port,socket.AF_INET6 if proto=='udp6' else socket.AF_INET)
  return {'test':test,'status':'ATTEMPTED','datagram_send_returned':sent,'error_class':err,'expected_rule':rule,'qualification':'REQUIRES_NFT_COUNTER_DELTA'}
 connected,err=_tcp(host,port,socket.AF_INET6 if proto=='tcp6' else socket.AF_INET)
 return {'test':test,'status':'ATTEMPTED','connected':connected,'error_class':err,'expected_rule':rule,'qualification':'REQUIRES_NFT_COUNTER_DELTA' if rule is not None else 'CONNECT_RESULT_REQUIRED'}
def main():
 if len(sys.argv)>1 and sys.argv[1]=='--child':
  test=sys.argv[2]
  host,port=DEST[test]; connected,err=_tcp(host,port,socket.AF_INET)
  print(json.dumps({'connected':connected,'error_class':err,'attempted':True},sort_keys=True,separators=(',',':'))); return 0
 if len(sys.argv)!=2 or sys.argv[1] not in PLAN: print(json.dumps({'status':'BLOCKED','reason':'TEST_NAME_NOT_ALLOWED'},separators=(',',':'))); return 2
 try:
  out=run(sys.argv[1]); print(json.dumps(out,sort_keys=True,separators=(',',':'))); return 0 if out['status'] in ('PASS','ATTEMPTED','NOT_TESTABLE') else 3
 except Exception as e: print(json.dumps({'status':'BLOCKED','reason':str(e)},sort_keys=True,separators=(',',':'))); return 3
if __name__=='__main__': raise SystemExit(main())
