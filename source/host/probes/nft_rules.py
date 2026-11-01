#!/usr/bin/env python3
"""Exact normalized nft table readback and packet-counter evidence."""
import argparse,json,re,subprocess,sys
TABLE='watson_s1_egress'
OUTPUT=['meta skuid {uid} jump collector']
COLLECTOR=[
 'ip daddr 127.0.0.53 udp dport 53 counter accept',
 'ip daddr 127.0.0.53 tcp dport 53 counter accept',
 'ip daddr 169.254.0.0/16 counter reject',
 'ip6 daddr fe80::/10 counter reject',
 'ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter reject',
 'ip6 daddr { ::1, fc00::/7 } counter reject',
 'tcp dport 443 counter accept',
 'counter reject']
HEADER='type filter hook output priority 0; policy accept;'
def norm(s):
 s=re.sub(r'#\s*handle\s+\d+','',s)
 s=re.sub(r'counter packets\s+\d+ bytes\s+\d+','counter',s)
 s=re.sub(r'priority\s+filter','priority 0',s)
 s=re.sub(r'\breject with icmp 3\b','reject',s)
 s=re.sub(r'\breject with icmpv6 4\b','reject',s)
 return ' '.join(s.strip().split())
def expected_from_source(path,uid):
 text=open(path,encoding='utf-8').read()
 if text.count('__WATSON_S1_UID__')!=1: raise ValueError('NFT_UID_TOKEN_NOT_UNIQUE')
 text=text.replace('__WATSON_S1_UID__',str(uid))
 rules={'output':[],'collector':[]}; current=None; header=[]; chain_names=[]; table_headers=[]
 for raw in text.splitlines():
  line=raw.split('#',1)[0].strip()
  if not line: continue
  if line.startswith('table '): table_headers.append(norm(line)); continue
  m=re.match(r'chain\s+(\w+)\s*\{(.*)$',line)
  if m:
   current=m.group(1)
   if current not in ('output','collector'):raise ValueError('NFT_TEMPLATE_UNEXPECTED_CHAIN')
   chain_names.append(current); tail=m.group(2).strip()
   if tail and not tail.startswith('}'):
    if current=='output' and tail.startswith('type '): header.append(norm(tail))
    elif not tail.startswith('type '): rules[current].append(norm(tail))
   continue
  if current and line=='}': current=None; continue
  if current:
   if current=='output' and line.startswith('type '): header.append(norm(line))
   elif line: rules[current].append(norm(line))
 if table_headers!=[f'table inet {TABLE} {{'] or chain_names!=['output','collector']: raise ValueError('NFT_TEMPLATE_TABLE_OR_CHAIN_SET_MISMATCH')
 if rules['output']!=[f'meta skuid {uid} jump collector']: raise ValueError('NFT_TEMPLATE_OUTPUT_RULE_MISMATCH')
 if rules['collector']!=[norm(x) for x in COLLECTOR]: raise ValueError('NFT_TEMPLATE_COLLECTOR_RULE_MISMATCH')
 return {'output_header':norm(HEADER),'rules':rules}
def read_table(uid,source):
 exp=expected_from_source(source,uid)
 p=subprocess.run(['sudo','-n','nft','-n','-a','list','table','inet',TABLE],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=5)
 if p.returncode: raise RuntimeError('NFT_READBACK_FAILED:'+str(p.returncode))
 actual={'output_header':None,'rules':{'output':[],'collector':[]}}; chain=None; chain_names=[]; table_headers=[]
 for raw in p.stdout.splitlines():
  line=re.sub(r'\s+#\s*handle\s+\d+\s*$','',raw).strip()
  if line.startswith('table '): table_headers.append(norm(line)); continue
  if re.match(r'(set|map|flowtable)\s',line):raise RuntimeError('NFT_UNEXPECTED_TABLE_OBJECT')
  m=re.match(r'chain\s+(\w+)\s*\{(.*)$',line)
  if m:
   chain=m.group(1)
   if chain not in ('output','collector'):raise RuntimeError('NFT_UNEXPECTED_CHAIN')
   chain_names.append(chain); rest=m.group(2).strip()
   if chain=='collector' and rest:raise RuntimeError('NFT_COLLECTOR_CHAIN_HEADER_UNEXPECTED')
   if rest and rest!='}':
    if chain=='output' and rest.startswith('type '): actual['output_header']=norm(rest)
    elif not rest.startswith('type '): actual['rules'][chain].append(norm(rest))
   continue
  if chain and line=='}': chain=None; continue
  if chain and line:
   if chain=='output' and line.startswith('type '): actual['output_header']=norm(line)
   elif line: actual['rules'][chain].append(norm(line))
 if table_headers!=[f'table inet {TABLE} {{'] or chain_names!=['output','collector']: raise RuntimeError('NFT_TABLE_OR_CHAIN_SET_MISMATCH')
 if actual!=exp: raise RuntimeError('NFT_NORMALIZED_READBACK_MISMATCH:'+json.dumps({'expected':exp,'actual':actual},sort_keys=True))
 counters={'output':[],'collector':[]}; chain=None
 for raw in p.stdout.splitlines():
  line=re.sub(r'\s+#\s*handle\s+\d+\s*$','',raw).strip(); m=re.match(r'chain\s+(output|collector)\s*\{',line)
  if m: chain=m.group(1); continue
  if chain and line=='}': chain=None; continue
  if chain and 'counter packets ' in line:
   m=re.search(r'counter packets\s+(\d+) bytes\s+(\d+)',line)
   if not m: raise RuntimeError('NFT_COUNTER_PARSE_FAILED')
   counters[chain].append({'packets':int(m.group(1)),'bytes':int(m.group(2))})
 if len(counters['collector'])!=8: raise RuntimeError('NFT_COLLECTOR_COUNTER_COUNT_MISMATCH')
 return {'uid':int(uid),'table':TABLE,'normalized':actual,'counters':counters,'raw_sha256':__import__('hashlib').sha256(p.stdout.encode()).hexdigest()}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--uid',type=int,required=True); ap.add_argument('--source',required=True); ap.add_argument('--assert-delta',nargs=3,metavar=('BEFORE','AFTER','RULE')); a=ap.parse_args()
 try:
  if a.assert_delta:
   before=json.load(open(a.assert_delta[0])); after=json.load(open(a.assert_delta[1])); rule=a.assert_delta[2]
   if before.get('normalized')!=after.get('normalized') or before.get('uid')!=after.get('uid') or before.get('table')!=after.get('table'): raise RuntimeError('NFT_RULESET_CHANGED_DURING_TEST')
   b=before['counters']; c=after['counters']
   if rule=='unchanged':
    if b!=c: raise RuntimeError('NFT_COUNTER_CHANGED_FOR_UBUNTU_CONTROL')
    delta=0
   elif rule=='dns-any':
    delta=sum(c['collector'][i]['packets']-b['collector'][i]['packets'] for i in (0,1))
    if delta<1: raise RuntimeError('NFT_DNS_ALLOW_COUNTER_NO_DELTA')
   else:
    chain,index=rule.split(':',1); index=int(index)
    delta=c[chain][index]['packets']-b[chain][index]['packets']
    if delta<1: raise RuntimeError('NFT_EXPECTED_RULE_COUNTER_NO_DELTA:'+rule)
   print(json.dumps({'status':'PASS','counter_rule':rule,'packet_delta':delta,'normalized_rules_unchanged':True},sort_keys=True))
  else:
   r=read_table(a.uid,a.source); print(json.dumps(r,sort_keys=True))
  return 0
 except Exception as e: print(json.dumps({'status':'BLOCKED','reason':str(e)},sort_keys=True)); return 3
if __name__=='__main__': raise SystemExit(main())
