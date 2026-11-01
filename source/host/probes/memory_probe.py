#!/usr/bin/env python3
"""Bounded cgroup-v2 OOM qualification; explicit opt-in, no retry."""
import json,os,pathlib,signal,subprocess,sys,time
from cgroup_utils import CgroupEvidenceError,locate_process_cgroup,read_actual_files
LIMIT=536870912

def _kv(text): return {k:int(v) for k,v in (line.split() for line in text.splitlines() if len(line.split())==2)}
def _host_health():
    mem=pathlib.Path('/proc/meminfo').read_text(); row=next((x for x in mem.splitlines() if x.startswith('MemAvailable:')),None)
    if row is None: raise CgroupEvidenceError('HOST_MEMAVAILABLE_MISSING')
    avail=int(row.split()[1]); load=pathlib.Path('/proc/loadavg').read_text().split()
    if not load: raise CgroupEvidenceError('HOST_LOADAVG_MISSING')
    return {'mem_available_kb':avail,'loadavg_1m':load[0]}
def _child():
    blocks=[]
    for _ in range(22):
        b=bytearray(32*1024*1024)
        for i in range(0,len(b),4096): b[i]=1
        blocks.append(b); time.sleep(.15)
    time.sleep(2)
    return 0
def main():
    if len(sys.argv)>1 and sys.argv[1]=='--child': return _child()
    if os.environ.get('ST01R_RUN_HOST_TESTS')!='1': print(json.dumps({'status':'BLOCKED','reason':'ST01R_RUN_HOST_TESTS_REQUIRED'},separators=(',',':'))); return 2
    unit=os.environ.get('ST01R_UNIT_NAME','')
    if not unit: print(json.dumps({'status':'BLOCKED','reason':'ST01R_UNIT_NAME_REQUIRED'},separators=(',',':'))); return 2
    try:
        loc,before_files=read_actual_files(('memory.max','memory.events','memory.peak','memory.swap.current','memory.swap.max'))
        if before_files['memory.max']!=str(LIMIT): raise CgroupEvidenceError('MEMORY_CGROUP_LIMIT_MISMATCH')
        if os.environ.get('ST01R_OOM_POLICY')!='continue': raise CgroupEvidenceError('OOM_POLICY_NOT_CONFIRMED_BY_OUTSIDE_OBSERVER')
        swap_total=int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('SwapTotal:')))
        if swap_total>0 and (os.environ.get('ST01R_SWAP_ZERO')!='1' or before_files['memory.swap.max']!='0'):
            raise CgroupEvidenceError('SWAP_NOT_DISABLED_FOR_NEGATIVE_TEST')
        before=_kv(before_files['memory.events']); peak0=int(before_files['memory.peak']); host0=_host_health()
        start=time.monotonic(); proc=subprocess.Popen([sys.executable,__file__,'--child'])
        child_loc=locate_process_cgroup(proc.pid)
        if child_loc['proc_cgroup']!=loc['proc_cgroup'] or child_loc['path']!=loc['path']:
            proc.kill(); proc.wait(); raise CgroupEvidenceError('OOM_CHILD_OUTSIDE_OBSERVED_CGROUP')
        try: rc=proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill(); rc=proc.wait()
        elapsed=time.monotonic()-start
        loc2,after_files=read_actual_files(('memory.max','memory.events','memory.peak','memory.swap.current','memory.swap.max'))
        if loc2['path']!=loc['path']: raise CgroupEvidenceError('CGROUP_PATH_CHANGED_DURING_TEST')
        after=_kv(after_files['memory.events']); delta={k:after.get(k,0)-before.get(k,0) for k in set(before)|set(after)}
        peak=max(peak0,int(after_files['memory.peak'])); host1=_host_health(); sigkill=rc==-signal.SIGKILL
        ok=(delta.get('oom_kill',0)>=1 and sigkill and delta.get('max',0)>=1 and after_files['memory.max']==str(LIMIT) and peak<=LIMIT and host0['mem_available_kb']>0 and host1['mem_available_kb']>0)
        result={'status':'PASS' if ok else 'UNQUALIFIED','actual_cgroup_path':str(loc['path']),'memory_max':after_files['memory.max'],'memory_peak':peak,'memory_events_delta':delta,'child_returncode':rc,'child_sigkill':sigkill,'elapsed_seconds':round(elapsed,3),'swap_total_kb':swap_total,'memory_swap_max':after_files['memory.swap.max'],'host_before':host0,'host_after':host1,'systemd_oom_policy_expected':os.environ.get('ST01R_OOM_POLICY')}
        print(json.dumps(result,sort_keys=True,separators=(',',':'))); return 0 if ok else 4
    except (OSError,ValueError,KeyError,StopIteration,CgroupEvidenceError,subprocess.TimeoutExpired) as e:
        print(json.dumps({'status':'UNQUALIFIED','reason':str(e)},sort_keys=True)); return 4
if __name__=='__main__': raise SystemExit(main())
