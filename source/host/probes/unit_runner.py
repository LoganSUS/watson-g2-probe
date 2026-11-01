#!/usr/bin/env python3
"""Run a fixed-property transient unit and independently observe its live cgroup."""
import argparse,json,os,pathlib,re,subprocess,sys,time
from cgroup_utils import CgroupEvidenceError,locate_process_cgroup,ancestor_limits,parse_systemd_usec
BASE={"User":"watson-s1","Group":"watson-s1","MemoryMax":"536870912","TasksMax":"16","NoNewPrivileges":"yes","PrivateTmp":"yes","ProtectSystem":"strict","ProtectHome":"yes","WorkingDirectory":"/opt/watson-s1","ReadWritePaths":"/var/lib/watson-s1/runs"}
PROPS=','.join((*BASE.keys(),'CPUQuotaPerSecUSec','LoadState','ActiveState','SubState','ControlGroup','MainPID','Result','OOMPolicy','MemorySwapMax','RuntimeMaxUSec','Environment'))
def load_props(path):
 rows=[]
 for raw in pathlib.Path(path).read_text().splitlines():
  line=raw.strip()
  if not line or line.startswith('#'):continue
  if '=' not in line:raise CgroupEvidenceError('UNIT_PROPS_ROW_INVALID')
  k,v=line.split('=',1);rows.append((k,v))
 values={k:v for k,v in rows if k!='Environment'}
 env=[v for k,v in rows if k=='Environment']
 expected_file={'User':'watson-s1','Group':'watson-s1','MemoryMax':'536870912','CPUQuota':'60%','TasksMax':'16','NoNewPrivileges':'yes','PrivateTmp':'yes','ProtectSystem':'strict','ProtectHome':'yes','ReadWritePaths':'/var/lib/watson-s1/runs','WorkingDirectory':'/opt/watson-s1'}
 counts={k:sum(1 for rk,_ in rows if rk==k) for k,_ in rows}
 if any(v!=1 for k,v in counts.items() if k!='Environment') or values!=expected_file or env!=['WATSON_S1_OUTPUT_ROOT=/var/lib/watson-s1/runs','PYTHONDONTWRITEBYTECODE=1']:
  raise CgroupEvidenceError('UNIT_PROPS_FILE_NOT_CANONICAL')
 return rows
def show(unit):
 p=subprocess.run(['sudo','-n','systemctl','show','--no-pager',f'--property={PROPS}','--',unit],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=4)
 if p.returncode:raise CgroupEvidenceError('OUTSIDE_SYSTEMD_SHOW_FAILED')
 d={}
 for line in p.stdout.splitlines():
  if '=' in line:k,v=line.split('=',1);d[k]=v
 return d
def verify_live(unit,d):
 if d.get('LoadState')!='loaded' or d.get('ActiveState')!='active':raise CgroupEvidenceError('UNIT_NOT_OBSERVED_ACTIVE')
 for k,v in BASE.items():
  if d.get(k,'').strip().lower()!=v.lower():raise CgroupEvidenceError('UNIT_PROPERTY_MISMATCH:'+k)
 try:
  if parse_systemd_usec(d.get('CPUQuotaPerSecUSec','')) != 600000: raise CgroupEvidenceError('UNIT_PROPERTY_MISMATCH:CPUQuotaPerSecUSec')
 except CgroupEvidenceError as e: raise CgroupEvidenceError('UNIT_PROPERTY_MISMATCH:CPUQuotaPerSecUSec') from e
 pid=int(d.get('MainPID','0'))
 if pid<1:raise CgroupEvidenceError('UNIT_MAINPID_MISSING')
 loc=locate_process_cgroup(pid)
 if loc['proc_cgroup']!=d.get('ControlGroup'): raise CgroupEvidenceError('OUTSIDE_CGROUP_MEMBERSHIP_MISMATCH')
 files={k:(loc['path']/k).read_text().strip() for k in ('memory.max','cpu.max','pids.max')}
 if files!={'memory.max':'536870912','cpu.max':'60000 100000','pids.max':'16'}:raise CgroupEvidenceError('OUTSIDE_CGROUP_LIMIT_MISMATCH')
 ancestors=ancestor_limits(loc['path'],loc['mountpoint'])
 for row in ancestors[1:]:
  mm=row.get('memory.max','max')
  if mm!='max' and mm.isdigit() and int(mm)<536870912:raise CgroupEvidenceError('ANCESTOR_MEMORY_LIMIT_STRICTER_THAN_UNIT')
  cm=row.get('cpu.max','max 100000').split()
  if len(cm)==2 and cm[0]!='max' and int(cm[0])/int(cm[1])<0.60:raise CgroupEvidenceError('ANCESTOR_CPU_LIMIT_STRICTER_THAN_UNIT')
  pm=row.get('pids.max','max')
  if pm!='max' and pm.isdigit() and int(pm)<16:raise CgroupEvidenceError('ANCESTOR_TASK_LIMIT_STRICTER_THAN_UNIT')
 return {'pid':pid,'proc_cgroup':loc['proc_cgroup'],'actual_cgroup_path':str(loc['path']),'actual_files':files,'ancestor_limits':ancestors}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--unit',required=True);ap.add_argument('--runtime',type=int,default=45);ap.add_argument('--oom-policy');ap.add_argument('--swap-zero',action='store_true');ap.add_argument('--props',default='/opt/watson-s1/host/watson_s1_unit.props');ap.add_argument('command',nargs=argparse.REMAINDER);a=ap.parse_args()
 if not re.fullmatch(r'watson-s1-[a-z0-9-]+\.service',a.unit) or not a.command:print(json.dumps({'status':'BLOCKED','reason':'BAD_UNIT_OR_COMMAND'}));return 2
 if a.command[0]=='--':a.command=a.command[1:]
 try:prop_rows=load_props(a.props)
 except Exception as e:print(json.dumps({'status':'BLOCKED','reason':str(e)}));return 3
 unitargs=['sudo','-n','systemd-run','--unit='+a.unit,'--uid=watson-s1','--gid=watson-s1','--wait','--collect','--pipe','--quiet',f'--property=RuntimeMaxSec={a.runtime}']
 for k,v in prop_rows:
  if k=='Environment':unitargs.append('--setenv='+v)
  else:unitargs.append(f'--property={k}={v}')
 if a.oom_policy:unitargs.append('--property=OOMPolicy='+a.oom_policy)
 if a.swap_zero:unitargs.append('--property=MemorySwapMax=0')
 for k,v in {'ST01R_RUN_HOST_TESTS':'1','ST01R_UNIT_NAME':a.unit,'ST01R_UNIT_RUNTIME_SEC':str(a.runtime)}.items():unitargs.append(f'--setenv={k}={v}')
 if a.oom_policy:unitargs.append('--setenv=ST01R_OOM_POLICY='+a.oom_policy)
 if a.swap_zero:unitargs.append('--setenv=ST01R_SWAP_ZERO=1')
 # Keep each unit alive briefly after its test so the external observer can inspect it.
 wrapper=['/bin/bash','-c','"$@"; rc=$?; sleep 0.35; exit $rc','st01r-unit-wrapper',*a.command]
 run_started=time.monotonic();p=subprocess.Popen(unitargs+['--']+wrapper,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 evidence=None; last_error=None; live_props=None; deadline=time.monotonic()+min(8,max(2,a.runtime))
 while time.monotonic()<deadline and p.poll() is None:
  try:
   d=show(a.unit)
   if d.get('ActiveState')=='active':
    evidence=verify_live(a.unit,d)
    if parse_systemd_usec(d.get('RuntimeMaxUSec',''))!=a.runtime*1000000:raise CgroupEvidenceError('RUNTIME_MAX_PROPERTY_MISMATCH')
    if a.oom_policy and d.get('OOMPolicy')!=a.oom_policy:raise CgroupEvidenceError('OOM_POLICY_MISMATCH')
    if a.swap_zero and d.get('MemorySwapMax')!='0':raise CgroupEvidenceError('MEMORY_SWAP_MAX_MISMATCH')
    expected_env={'WATSON_S1_OUTPUT_ROOT=/var/lib/watson-s1/runs','PYTHONDONTWRITEBYTECODE=1','ST01R_RUN_HOST_TESTS=1','ST01R_UNIT_NAME='+a.unit,'ST01R_UNIT_RUNTIME_SEC='+str(a.runtime)}
    if a.oom_policy:expected_env.add('ST01R_OOM_POLICY='+a.oom_policy)
    if a.swap_zero:expected_env.add('ST01R_SWAP_ZERO=1')
    if set(d.get('Environment','').split())!=expected_env:raise CgroupEvidenceError('UNIT_ENVIRONMENT_MISMATCH')
    live_props=d;break
  except Exception as e:last_error=str(e)
  time.sleep(.05)
 try:out,err=p.communicate(timeout=a.runtime+10)
 except subprocess.TimeoutExpired:
  p.kill();out,err=p.communicate();result={'status':'BLOCKED','reason':'UNIT_TIMEOUT','exit_code':p.returncode,'stdout':out.strip(),'stderr':err.strip(),'stdout_sha256':__import__('hashlib').sha256(out.encode()).hexdigest(),'stderr_sha256':__import__('hashlib').sha256(err.encode()).hexdigest()};print(json.dumps(result,sort_keys=True));return 4
 if evidence is None:
  print(json.dumps({'status':'BLOCKED','reason':last_error or 'LIVE_UNIT_NOT_OBSERVED','exit_code':p.returncode,'stdout':out.strip(),'stderr':err.strip(),'stdout_sha256':__import__('hashlib').sha256(out.encode()).hexdigest(),'stderr_sha256':__import__('hashlib').sha256(err.encode()).hexdigest()},sort_keys=True));return 3
 result={'status':'PASS' if p.returncode==0 else 'TEST_NONZERO','exit_code':p.returncode,'elapsed_seconds':round(time.monotonic()-run_started,3),'stdout_sha256':__import__('hashlib').sha256(out.encode()).hexdigest(),'stderr_sha256':__import__('hashlib').sha256(err.encode()).hexdigest(),'stdout':out.strip(),'stderr':err.strip(),'live_unit_evidence':evidence,'unit_properties':{k:live_props.get(k) for k in PROPS.split(',')}}
 print(json.dumps(result,sort_keys=True));return 0 if p.returncode==0 else 4
if __name__=='__main__':raise SystemExit(main())
