"""Recompute manuscript tables from saved observations; never alter raw results."""
from pathlib import Path
from collections import Counter, defaultdict
import csv, json, hashlib, statistics, sys, random
sys.stdout.reconfigure(encoding='utf-8')
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'reports/evidence_audit_20261012'
OUT.mkdir(parents=True, exist_ok=True)
inputs = {}
def read(path):
    p=ROOT/path
    inputs[path]=hashlib.sha256(p.read_bytes()).hexdigest()
    if p.suffix=='.csv':
        return list(csv.DictReader(p.open(encoding='utf-8-sig',newline='')))
    return json.loads(p.read_text(encoding='utf-8-sig'))
def save(name, rows):
    with (OUT/name).open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
J='experiments/revision/results/address_batch200_semantic_v0_5_eval_final/per_binary_metrics.csv'
rows=read(J); a=[r for r in rows if r['scope']=='all_functions']
assert len(rows)==7200
assert len({r['sample_id'] for r in a})==200
assert len({(r['sample_id'],r['condition']) for r in a})==400
assert set(r['run_status'] for r in a)=={'ok'}
metrics=['hit_1_expected','hit_3_expected','hit_5_expected','hit_10_expected','rr_expected']
summary=[]
for m in sorted({r['method'] for r in a}):
    rs=[r for r in a if r['method']==m]
    assert len(rs)==400
    summary.append({'method':m,'n':len(rs),**{k:statistics.mean(float(r[k]) for r in rs) for k in metrics}})
save('juliet_all_methods.csv',summary)
by={(r['sample_id'],r['condition'],r['method']):r for r in a}
paired=[]
for cwe in sorted({r['cwe'] for r in a}):
    pairs=[(r,by[r['sample_id'],r['condition'],'dangerous_plus_callchain']) for r in a if r['method']=='full_method' and r['cwe']==cwe]
    d=[float(x['expected_rank_conditional'])-float(y['expected_rank_conditional']) for x,y in pairs]
    paired.append({'cwe':cwe,'observations':len(pairs),'sample_ids':len({x['sample_id'] for x,y in pairs}),'wins':sum(x<0 for x in d),'ties':sum(x==0 for x in d),'losses':sum(x>0 for x in d),**{'delta_'+k:statistics.mean(float(x[k])-float(y[k]) for x,y in pairs) for k in metrics}})
save('juliet_paired_by_cwe.csv',paired)
old=read('experiments/revision/results/address_batch200_configured_eval/per_binary_metrics.csv')
keys=['population','candidate_count','rank_min','rank_max','tie_count','expected_rank_conditional']+metrics
cur={(r['sample_id'],r['condition'],r['scope'],r['method']):r for r in rows}
transport=0
for r in old:
    if r['method'] not in ['full_method','dangerous_plus_callchain']: continue
    s=cur[r['sample_id'],r['condition'],r['scope'],r['method']]
    for k in keys: assert r[k]==s[k],(k,r,s)
    transport+=1
bootstrap=read('experiments/revision/results/address_batch200_configured_eval/original/all_functions/paired_family_bootstrap.csv')
bootstrap=[r for r in bootstrap if r['baseline']=='dangerous_plus_callchain']
save('juliet_aggregate_bootstrap.csv',bootstrap)
within=read('reports/core_research_upgrade_20261012/juliet_family_bootstrap.csv')
# Reproduce within-CWE intervals from the original metric rows, preserving
# sample-pair clustering and the recorded shared RNG stream across metrics.
rng=random.Random(20261012)
for record in within:
    cwe=record['cwe']
    ids=sorted({r['sample_id'] for r in a if r['cwe']==cwe})
    assert len(ids)==50
    for label,field in [('top1','hit_1_expected'),('top5','hit_5_expected'),('mrr','rr_expected')]:
        vals=[statistics.mean(float(by[sid,c,'full_method'][field])-float(by[sid,c,'dangerous_plus_callchain'][field]) for c in ['original','stripped']) for sid in ids]
        boot=sorted(statistics.mean(vals[rng.randrange(50)] for _ in range(50)) for _ in range(10000))
        assert abs(statistics.mean(vals)-float(record[f'delta_{label}_mean']))<1e-12
        assert abs(boot[250]-float(record[f'delta_{label}_ci95_low']))<1e-12
        assert abs(boot[9749]-float(record[f'delta_{label}_ci95_high']))<1e-12
save('juliet_within_cwe_bootstrap.csv',within)
representation=[]
for m in ['full_method','dangerous_plus_callchain']:
    shifts=[]
    for sid in sorted({r['sample_id'] for r in a}):
        x=by[sid,'original',m];y=by[sid,'stripped',m]
        for k in metrics: assert x[k]==y[k]
        shifts.append(abs(float(x['expected_rank_conditional'])/float(x['population'])-float(y['expected_rank_conditional'])/float(y['population'])))
    representation.append({'method':m,'pairs':len(shifts),'mean_abs_normalized_rank_shift':statistics.mean(shifts)})
save('representation.csv',representation)
cohort=[]; statuses=[]; structural=[]; cohort_methods={}
for tag,path in [('holdout','holdout_20261008'),('distribution','distribution_20261008')]:
    rs=read(f'experiments/revision/realworld/{path}/evaluation_frozen/per_condition.csv')
    fields=['case_id','project','version','condition','method','status','population','scored_count','rank_min','rank_max']
    for r in rs:
        if r['method'] in ['structural_v05','argument_role_v02']:
            structural.append({'cohort':tag,**{k:r.get(k,'') for k in fields}})
    n=len({r['case_id'] for r in rs}); ms=sorted({r['method'] for r in rs});counts=Counter(r['status'] for r in rs)
    cohort_methods[tag]=ms
    cohort.append({'cohort':tag,'conditions':n,'methods':len(ms),'rows':len(rs),**dict(counts)})
    statuses.extend({'cohort':tag,'status':s,'n':v} for s,v in counts.items())
save('cohort_status.csv',statuses);save('realworld_structural_and_role_ranks.csv',structural)
dev=read('experiments/revision/realworld/results/fixed_budget_development_20261008/evaluation/per_case_metrics.csv')
native=read('experiments/revision/realworld/results/fixed_budget_development_20261008/native_external_results.csv')
devby={(r['case_id'],r['method']):r for r in dev}
ok=[r for r in dev if r['method']=='cwe_checker_warning_count_adapter' and r['status']=='ok']
assert len(ok)==7
nativeby={r['case_id']:r for r in native}
for r in ok:
    f=devby[r['case_id'],'full_method']; n=nativeby[r['case_id']]
    assert f['status']=='ok' and n['status']=='ok' and n['task_supported']=='1'
    assert f['population']==r['population']==n['population']
    assert f['target']==r['target']==n['target_id']
    assert f['scored_count']==r['scored_count']==r['population']
assert sum(r['method']=='cwe_checker_warning_count_adapter' and r['status']=='analysis_failure' for r in dev)==5
external=[]
for k in [1,3,5,10]:
    field=f'hit_top{k}_expected'
    external.append({'metric':f'Top-{k}','development_success_n':7,'full':statistics.mean(float(devby[r['case_id'],'full_method'][field]) for r in ok),'adapter':statistics.mean(float(r[field]) for r in ok)})
save('development_external_comparison.csv',external)
selected=read('experiments/legacy/manifests/batch200_sources.csv')
build=read('experiments/legacy/manifests/batch200_manifest.csv')
strip=read('experiments/revision/stripped/manifest.csv')
assert len(selected)==len(build)==len(strip)==200
assert Counter(r['cwe'] for r in selected)==Counter({'CWE-121':50,'CWE-122':50,'CWE-134':50,'CWE-78':50})
assert set(r['build_status'] for r in build)=={'built'}
for r in strip:
    assert all(r[k]=='1' for k in ['text_identical','symtab_removed','debug_removed','target_symbol_removed'])
recovery=[]
for tag,p in [('development','bridge_v03_development_20261010'),('retrospective_holdout','bridge_v03_retrospective_holdout_20261010')]:
    d=read('experiments/revision/realworld/'+p+'/summary.json')
    for r in d['runs']:
        recovery.append({'cohort':tag,'binary':r['binary'],'events':r['event_count'],'contractions':r['contraction_events'],'invalid_contract_events':r['invalid_contract_events']})
save('recovery_counts.csv',recovery)
z=read('experiments/revision/realworld/zlib_fixed_witness_20261010/runs/manifest_full.json')
zr=z.get('results',z.get('runs',[]))
if not zr:
    zr=next(v for v in z.values() if isinstance(v,list) and len(v)==8640)
assert len(zr)==8640
zout=[]
for v in ['1.2.11','1.2.12']:
    vv=[r for r in zr if r['version']==v]
    zout.append({'version':v,'invocations':len(vv),'nonzero_exit':sum(r['returncode']!=0 for r in vv)})
save('zlib_matrix_counts.csv',zout)
out={'juliet_rows':len(rows),'juliet_conditions':400,'juliet_sample_ids':200,'transport_matched_rows':transport,'within_cwe_bootstrap_recomputed':True,'development_support_population_target_verified':True,'cohorts':cohort,'reporting_methods':cohort_methods,'development_success_cases':[r['case_id'] for r in ok],'source_template_families':len({r['family'] for r in a}),'checks':'all assertions passed','input_sha256':inputs}
(OUT/'reconciliation.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in out.items() if k!='input_sha256'},ensure_ascii=False,indent=2))
