from pathlib import Path
import csv, random, statistics, json
root=Path(r"C:\Users\孙科锦\Desktop\期刊论文\项目\官方模板\被拒修改版")
p=root/'reports/core_research_upgrade_20261012/juliet_paired_full_vs_baseline.csv'
rows=list(csv.DictReader(p.open(encoding='utf-8-sig')))
for r in rows:
    for k in ['delta_top1','delta_top5','delta_mrr']:
        r[k]=float(r[k])
clusters={}
for r in rows:
    clusters.setdefault(r['cwe'],{}).setdefault(r['sample_id'],[]).append(r)
rng=random.Random(20261012)
out=[]
for cwe, ss in sorted(clusters.items()):
    vals=[]
    for sid, rr in ss.items():
        vals.append({k:statistics.mean(x[k] for x in rr) for k in ['delta_top1','delta_top5','delta_mrr']})
    record={'cwe':cwe,'clusters':len(vals)}
    for k in ['delta_top1','delta_top5','delta_mrr']:
        point=statistics.mean(v[k] for v in vals)
        boots=[]
        for _ in range(10000):
            sample=[vals[rng.randrange(len(vals))][k] for __ in vals]
            boots.append(statistics.mean(sample))
        boots.sort()
        record[k+'_mean']=point
        record[k+'_ci95_low']=boots[250]
        record[k+'_ci95_high']=boots[9749]
    out.append(record)
outp=root/'reports/core_research_upgrade_20261012/juliet_family_bootstrap.csv'
with outp.open('w',encoding='utf-8',newline='') as fh:
    w=csv.DictWriter(fh,fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
print(json.dumps(out,indent=2))
