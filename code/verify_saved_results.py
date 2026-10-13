"""Portable saved-result audit. Uses standard-library modules only."""
from pathlib import Path
from collections import Counter
from decimal import Decimal,ROUND_HALF_UP
import csv,json,hashlib,statistics
R=Path(__file__).resolve().parent
checks={}
def read(p):
 p=R/p
 if p.suffix=='.csv':return list(csv.DictReader(p.open(encoding='utf-8-sig',newline='')))
 return json.loads(p.read_text(encoding='utf8'))
def record(name,got,want):
 assert got==want,(name,got,want)
 checks[name]={'value':got,'status':'PASS'}
def fmt(v,n=4):return format(Decimal(str(v)).quantize(Decimal(1).scaleb(-n),rounding=ROUND_HALF_UP),'f')
manifest=read('file_manifest.json')
for x in manifest:assert hashlib.sha256((R/x['path']).read_bytes()).hexdigest()==x['sha256'],x['path']
checks['copied_file_hashes']={'status':'PASS','files':len(manifest)}
A='reports/evidence_audit_20261012/'
rows=read('experiments/revision/results/address_batch200_semantic_v0_5_eval_final/per_binary_metrics.csv')
allf=[r for r in rows if r['scope']=='all_functions']
record('Juliet sample IDs',len({r['sample_id'] for r in allf}),200)
record('Juliet symbol conditions',len({(r['sample_id'],r['condition']) for r in allf}),400)
by={(r['sample_id'],r['condition'],r['method']):r for r in allf}
for summary in read(A+'juliet_all_methods.csv'):
 rr=[r for r in allf if r['method']==summary['method']]
 record('Juliet method denominator/'+summary['method'],len(rr),400)
 for key in ['hit_1_expected','hit_5_expected','rr_expected']:
  record(summary['method']+'/'+key,fmt(statistics.mean(float(r[key]) for r in rr)),fmt(summary[key]))
for summary in read(A+'juliet_paired_by_cwe.csv'):
 pairs=[(r,by[r['sample_id'],r['condition'],'dangerous_plus_callchain']) for r in allf if r['method']=='full_method' and r['cwe']==summary['cwe']]
 delta=[float(x['expected_rank_conditional'])-float(y['expected_rank_conditional']) for x,y in pairs]
 record(summary['cwe']+'/wins ties losses',[sum(d<0 for d in delta),sum(d==0 for d in delta),sum(d>0 for d in delta)],[int(summary[k]) for k in ['wins','ties','losses']])
 for key in ['hit_1_expected','hit_5_expected','rr_expected']:
  record(summary['cwe']+'/'+key,fmt(statistics.mean(float(x[key])-float(y[key]) for x,y in pairs)),fmt(summary['delta_'+key]))
for m in ['full_method','dangerous_plus_callchain']:
 for sid in {r['sample_id'] for r in allf}:
  for key in ['hit_1_expected','hit_5_expected']:
   assert by[sid,'original',m][key]==by[sid,'stripped',m][key],(sid,m,key)
record('Representation pairs per method',200,200)
for cohort,want in [('holdout_20261008',{'ok':170,'incomplete_scores':16,'analysis_failure':6}),('distribution_20261008',{'ok':24,'incomplete_scores':8})]:
 rr=read(f'experiments/revision/realworld/{cohort}/evaluation_frozen/per_condition.csv')
 record(cohort+'/method-record states',dict(Counter(r['status'] for r in rr)),want)
role=[];structure=[]
for c in ['holdout_20261008','distribution_20261008']:
 rr=read(f'experiments/revision/realworld/{c}/evaluation_frozen/per_condition.csv')
 role += [r for r in rr if r['method']=='argument_role_v02']
 structure += [r for r in rr if r['method']=='structural_v05']
record('Role-comparator complete conditions',sum(r['status']=='ok' for r in role),8)
record('Structural-score complete conditions',sum(r['status']=='ok' for r in structure),14)
dev=read('experiments/revision/realworld/results/fixed_budget_development_20261008/evaluation/per_case_metrics.csv')
db={(r['case_id'],r['method']):r for r in dev}
ok=[r for r in dev if r['method']=='cwe_checker_warning_count_adapter' and r['status']=='ok']
record('Jointly successful development adapter conditions',len(ok),7)
record('Failed development adapter conditions',sum(r['method']=='cwe_checker_warning_count_adapter' and r['status']=='analysis_failure' for r in dev),5)
for k in [1,3,5,10]:
 key=f'hit_top{k}_expected';saved=next(r for r in read(A+'development_external_comparison.csv') if r['metric']==f'Top-{k}')
 for label,rr in [('full',[db[r['case_id'],'full_method'] for r in ok]),('adapter',ok)]:
  record(f'Development Top-{k}/'+label,fmt(statistics.mean(float(r[key]) for r in rr),3),fmt(saved[label],3))
z=read('experiments/revision/realworld/zlib_fixed_witness_20261010/runs/manifest_full.json')['results']
record('zlib invocations',dict(Counter(r['version'] for r in z)),{'1.2.11':4320,'1.2.12':4320})
record('zlib nonzero exits',dict(Counter(r['version'] for r in z if r['returncode']!=0)),{'1.2.11':1140})
for c,want in [('bridge_v03_development_20261010',[27178,840]),('bridge_v03_retrospective_holdout_20261010',[6241,1034])]:
 events=contractions=0
 for f in sorted((R/'experiments/revision/realworld'/c).glob('*/recovery_events.jsonl')):
  prev='0'*64;population=None
  for line in f.read_text(encoding='utf8').splitlines():
   e=json.loads(line);saved=e.pop('event_sha256')
   digest=hashlib.sha256(json.dumps(e,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf8')).hexdigest()
   assert digest==saved and e['prev_event_sha256']==prev,f
   prev=saved;before=e['interval_before'];after=e['interval_after']
   assert before[0]<=after[0]<=after[1]<=before[1],(f,e['candidate_id'])
   if e['timeout'] or e['exception']:assert before==after
   if population is not None:assert population==e['candidate_pool_sha256']
   population=e['candidate_pool_sha256'];events+=1
   contractions+=int(after!=before)
 record(c+'/events and contractions',[events,contractions],want)
reuse=read('experiments/revision/realworld/validation/arbiter_prefix_reuse_probe_20261008_controlled/enhanced_v4_final/results.json')
record('Prefix-reuse serial repetitions',len(reuse['runs']),2)
for run in reuse['runs']:
 a=run['baseline'];b=run.get('reuse',run.get('cached'))
 if b is None:b=next(v for k,v in run.items() if isinstance(v,dict) and k!='baseline' and 'counters' in v)
 assert a['report_signature']==b['report_signature']
 record('Prefix execution counts/'+str(run['repetition']),[a['counters']['prefix_executions'],b['counters']['prefix_executions'],b['counters']['prefix_cache_hits']],[3,1,2])
out={'status':'PASS','checks':checks,'scope':'Saved-record consistency checks; no binary experiment or bootstrap resampling was rerun.'}
(R/'verification_results.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
print('PASS:',len(checks),'saved-result checks;',len(manifest),'copied file hashes.')
