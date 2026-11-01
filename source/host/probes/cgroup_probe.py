#!/usr/bin/env python3
"""Read-only proof for the live process's transient systemd cgroup v2."""
import os,sys
from cgroup_utils import CgroupEvidenceError,ancestor_limits,read_actual_files,systemd_show,json_emit

def main():
    unit=os.environ.get("ST01R_UNIT_NAME","")
    if not unit: print("BLOCKED: ST01R_UNIT_NAME missing"); return 2
    try:
        loc,values=read_actual_files(("memory.max","memory.peak","memory.events","memory.swap.current","cpu.max","cpu.stat","pids.max","cgroup.controllers"))
        try:
            props,verified=systemd_show(unit)
            if loc['path']!=verified['path']: raise CgroupEvidenceError('CGROUP_PATH_CHANGED_DURING_PROBE')
            self_systemd={'status':'MATCH','properties':props}
        except CgroupEvidenceError as e:
            if not str(e).startswith('SYSTEMD_SHOW_FAILED:'): raise
            self_systemd={'status':'UNAVAILABLE_OUTSIDE_OBSERVER_REQUIRED','reason':str(e)}
        if values["memory.max"]!="536870912" or values["cpu.max"]!="60000 100000" or values["pids.max"]!="16":
            raise CgroupEvidenceError("ACTUAL_CGROUP_LIMIT_MISMATCH")
        result={"status":"PASS","cgroup_v2":True,"proc_cgroup":loc["proc_cgroup"],"actual_cgroup_path":str(loc["path"]),"cgroup_files":values,"ancestor_limits":ancestor_limits(loc["path"],loc["mountpoint"]),"self_systemd_observation":self_systemd}
        json_emit(result); return 0
    except (OSError,ValueError,CgroupEvidenceError) as e:
        json_emit({"status":"BLOCKED","reason":str(e)}); return 3
if __name__=="__main__": raise SystemExit(main())
