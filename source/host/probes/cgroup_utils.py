#!/usr/bin/env python3
"""Fail-closed cgroup v2 discovery for the current process."""
import json, os, pathlib, re, subprocess
from decimal import Decimal, InvalidOperation

class CgroupEvidenceError(RuntimeError): pass

def parse_systemd_usec(value):
    text=str(value).strip()
    if not text or text in {'infinity','infinite','-'}: raise CgroupEvidenceError('SYSTEMD_DURATION_INVALID')
    factors={'us':Decimal(1),'µs':Decimal(1),'ms':Decimal(1000),'s':Decimal(1000000),'min':Decimal(60000000),'m':Decimal(60000000),'h':Decimal(3600000000),'d':Decimal(86400000000)}
    token=re.compile(r'\s*(\d+(?:\.\d+)?)(us|µs|ms|min|m|s|h|d)')
    pos=0;total=Decimal(0)
    while pos<len(text):
        m=token.match(text,pos)
        if not m: raise CgroupEvidenceError('SYSTEMD_DURATION_INVALID')
        try: total+=Decimal(m.group(1))*factors[m.group(2)]
        except InvalidOperation as e: raise CgroupEvidenceError('SYSTEMD_DURATION_INVALID') from e
        pos=m.end()
    if total!=total.to_integral_value(): raise CgroupEvidenceError('SYSTEMD_DURATION_SUBMICROSECOND')
    return int(total)

def _unescape_mount(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)

def locate_process_cgroup(pid=None,proc_root="/proc", sys_root="/sys/fs/cgroup"):
    proc = pathlib.Path(proc_root)
    member_path=proc/str(pid)/"cgroup" if pid is not None else proc/"self/cgroup"
    rows = [line.split(":", 2) for line in member_path.read_text().splitlines() if line]
    v2 = [r for r in rows if len(r)==3 and r[0]=="0" and r[1]==""]
    if len(v2)!=1: raise CgroupEvidenceError("CGROUP_V2_MEMBERSHIP_NOT_UNIQUE")
    rel = pathlib.PurePosixPath(v2[0][2])
    if not rel.is_absolute() or ".." in rel.parts: raise CgroupEvidenceError("CGROUP_MEMBERSHIP_PATH_INVALID")
    mounts=[]
    for line in (proc/"self/mountinfo").read_text().splitlines():
        if " - " not in line: continue
        left,right=line.split(" - ",1); lf=left.split(); rf=right.split()
        if len(lf)>=5 and rf and rf[0]=="cgroup2": mounts.append((_unescape_mount(lf[3]),_unescape_mount(lf[4])))
    matches=[]
    for mount_root,mountpoint in mounts:
        root=pathlib.PurePosixPath(mount_root); mp=pathlib.Path(mountpoint).resolve(strict=True)
        if root==pathlib.PurePosixPath("/") or rel==root or str(rel).startswith(str(root).rstrip("/")+"/"):
            suffix=pathlib.PurePosixPath(*rel.parts[len(root.parts):]) if root!=pathlib.PurePosixPath("/") else pathlib.PurePosixPath(*rel.parts[1:])
            candidate=(mp.joinpath(*suffix.parts)).resolve(strict=True)
            if candidate==mp or mp in candidate.parents: matches.append((mp,candidate,str(rel)))
    if len(matches)!=1: raise CgroupEvidenceError("CGROUP2_MOUNT_MAPPING_NOT_UNIQUE")
    mount,group,proc_cgroup=matches[0]
    if not group.is_dir(): raise CgroupEvidenceError("PROCESS_CGROUP_NOT_DIRECTORY")
    return {"mountpoint":mount,"path":group,"proc_cgroup":proc_cgroup,"pid":pid}

def read_actual_files(names):
    loc=locate_process_cgroup(); base=loc["path"]; values={}
    for name in names:
        if "/" in name or name in (".","..") or name.startswith("."): raise CgroupEvidenceError("CGROUP_FILENAME_INVALID")
        p=base/name
        if not p.is_file(): raise CgroupEvidenceError("CGROUP_FILE_MISSING:"+name)
        values[name]=p.read_text().strip()
    return loc,values

def ancestor_limits(start=None,mountpoint=None):
    loc=locate_process_cgroup() if start is None else {"path":pathlib.Path(start),"mountpoint":pathlib.Path(mountpoint)}
    group=loc["path"]; mount=loc["mountpoint"]; rows=[]; p=group
    while True:
        row={"path":str(p)}
        for name in ("memory.max","memory.high","memory.swap.max","cpu.max","pids.max"):
            f=p/name
            row[name]=f.read_text().strip() if f.is_file() else "UNAVAILABLE"
        rows.append(row)
        if p==mount: break
        if p.parent==p or mount not in p.parents: raise CgroupEvidenceError("CGROUP_ANCESTOR_ESCAPE")
        p=p.parent
    return rows

def systemd_show(unit):
    if not re.fullmatch(r"watson-s1-[a-z0-9-]+\.service",unit): raise CgroupEvidenceError("UNIT_NAME_INVALID")
    props=("Id,LoadState,ActiveState,SubState,ControlGroup,User,Group,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,RuntimeMaxUSec,TasksMax,NoNewPrivileges,PrivateTmp,ProtectSystem,ProtectHome,ReadWritePaths,WorkingDirectory,OOMPolicy")
    p=subprocess.run(["systemctl","show","--no-pager",f"--property={props}","--",unit],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=5)
    if p.returncode: raise CgroupEvidenceError("SYSTEMD_SHOW_FAILED:"+str(p.returncode))
    out={}
    for line in p.stdout.splitlines():
        if "=" in line:
            k,v=line.split("=",1); out[k]=v
    if out.get("LoadState")!="loaded" or out.get("ActiveState")!="active": raise CgroupEvidenceError("UNIT_NOT_ACTIVE_DURING_EVIDENCE")
    loc=locate_process_cgroup(); ctl=out.get("ControlGroup","")
    actual="/"+str(loc["path"].relative_to(loc["mountpoint"]).as_posix()).lstrip("/")
    proc=loc["proc_cgroup"]
    if not ctl or ctl!=proc or proc!=actual: raise CgroupEvidenceError("SYSTEMD_CGROUP_MEMBERSHIP_MISMATCH")
    expected={"User":"watson-s1","Group":"watson-s1","MemoryMax":"536870912","TasksMax":"16","NoNewPrivileges":"yes","PrivateTmp":"yes","ProtectSystem":"strict","ProtectHome":"yes","WorkingDirectory":"/opt/watson-s1","ReadWritePaths":"/var/lib/watson-s1/runs"}
    bad={k:(out.get(k),v) for k,v in expected.items() if out.get(k," ").strip().lower()!=v.lower()}
    try:
        if parse_systemd_usec(out.get('CPUQuotaPerSecUSec','')) != 600000: bad['CPUQuotaPerSecUSec']=(out.get('CPUQuotaPerSecUSec'),'600000us')
    except CgroupEvidenceError: bad['CPUQuotaPerSecUSec']=(out.get('CPUQuotaPerSecUSec'),'600000us')
    expected_runtime=os.environ.get('ST01R_UNIT_RUNTIME_SEC','')
    if not expected_runtime.isdigit() or int(expected_runtime)<1:
        bad['RuntimeMaxUSec']=(out.get('RuntimeMaxUSec'),'ST01R_UNIT_RUNTIME_SEC_REQUIRED')
    else:
        try:
            if parse_systemd_usec(out.get('RuntimeMaxUSec','')) != int(expected_runtime)*1000000:
                bad['RuntimeMaxUSec']=(out.get('RuntimeMaxUSec'),str(int(expected_runtime)*1000000)+'us')
        except CgroupEvidenceError:
            bad['RuntimeMaxUSec']=(out.get('RuntimeMaxUSec'),str(int(expected_runtime)*1000000)+'us')
    if bad: raise CgroupEvidenceError("SYSTEMD_PROPERTY_MISMATCH:"+json.dumps(bad,sort_keys=True))
    return out,loc

def json_emit(obj): print(json.dumps(obj,sort_keys=True,separators=(",",":")))
