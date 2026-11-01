#!/usr/bin/env python3
"""15-second CPU quota proof from the current transient-unit cgroup."""
import json,os,pathlib,subprocess,sys,time
from cgroup_utils import CgroupEvidenceError,locate_process_cgroup,read_actual_files

def _stat(text): return {k:int(v) for k,v in (line.split() for line in text.splitlines() if len(line.split())==2)}
def _child():
    end=time.monotonic()+15; x=1
    while time.monotonic()<end: x=(x*1664525+1013904223)&0xffffffff
    return 0
def main():
    if len(sys.argv)>1 and sys.argv[1]=='--child': return _child()
    if os.environ.get('ST01R_RUN_HOST_TESTS')!='1': print(json.dumps({'status':'BLOCKED','reason':'ST01R_RUN_HOST_TESTS_REQUIRED'},separators=(',',':'))); return 2
    unit=os.environ.get('ST01R_UNIT_NAME','')
    if not unit: print(json.dumps({'status':'BLOCKED','reason':'ST01R_UNIT_NAME_REQUIRED'},separators=(',',':'))); return 2
    try:
        loc,before_files=read_actual_files(('cpu.max','cpu.stat'))
        if before_files['cpu.max']!='60000 100000' or not loc['proc_cgroup'].endswith('/'+unit): raise CgroupEvidenceError('CPU_CGROUP_PATH_OR_LIMIT_MISMATCH')
        before=_stat(before_files['cpu.stat']); started=time.monotonic(); proc=subprocess.Popen([sys.executable,__file__,'--child'])
        child_loc=locate_process_cgroup(proc.pid)
        if child_loc['proc_cgroup']!=loc['proc_cgroup'] or child_loc['path']!=loc['path']:
            proc.kill(); proc.wait(); raise CgroupEvidenceError('CPU_CHILD_OUTSIDE_OBSERVED_CGROUP')
        rc=proc.wait(timeout=18); elapsed=time.monotonic()-started
        loc2,after_files=read_actual_files(('cpu.max','cpu.stat'))
        if loc2['path']!=loc['path'] or after_files['cpu.max']!='60000 100000': raise CgroupEvidenceError('CPU_CGROUP_CHANGED_DURING_TEST')
        after=_stat(after_files['cpu.stat']); usage=after.get('usage_usec',0)-before.get('usage_usec',0); throttled=after.get('nr_throttled',0)-before.get('nr_throttled',0)
        ok=(rc==0 and elapsed>=14.5 and throttled>0 and usage<=650000*elapsed)
        print(json.dumps({'status':'PASS' if ok else 'UNQUALIFIED','actual_cgroup_path':str(loc['path']),'cpu_max':after_files['cpu.max'],'usage_usec_delta':usage,'nr_throttled_delta':throttled,'elapsed_seconds':round(elapsed,3),'systemd_cpu_quota_expected_usec':60000},sort_keys=True))
        return 0 if ok else 4
    except (OSError,ValueError,KeyError,CgroupEvidenceError,subprocess.TimeoutExpired) as e:
        print(json.dumps({'status':'UNQUALIFIED','reason':str(e)},sort_keys=True)); return 4
if __name__=='__main__': raise SystemExit(main())
