"""Frozen supplemental evaluation of published Debian Expat binaries.

No source code or debug sidecar is used. Dynamic target symbols are read only
after scoring. Public source exists; this is not a closed-source claim.
"""
import argparse
import csv
import hashlib
import json
import subprocess
import sys
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
REV = HERE.parent
PROJECT = REV.parents[1]
sys.path.insert(0, str(REV))
from address_model import score as structural
from argument_roles.score_roles import score_roles, write_outputs as write_roles
from fixed_budget import evaluate_by_case, _write_csv, _empty_metrics
sys.path.insert(0, str(HERE / 'baselines'))
from adapt_cwe_checker_warnings import map_warnings, address_key

IMAGE = 'ghcr.io/fkie-cad/cwe_checker@sha256:9990d5573af5c1ceb035ab9149374a41e3f2fe24230d871911dcaa7d7cbb2b74'
TARGETS = {
    'expat': ('CVE-2022-23852', 'XML_GetBuffer', {'CWE190'}),
    'libarchive': ('CVE-2016-1541', 'zip_read_mac_metadata', {'CWE119','CWE787'}),
    'libjpeg-turbo': ('CVE-2018-14498', 'get_8bit_row', {'CWE119','CWE125'}),
}
METHODS = ('structural_v05', 'argument_role_v02', 'random_uniform',
           'dangerous_match', 'dangerous_count', 'callchain_reachability', 'cfg_complexity',
           'dangerous_plus_callchain', 'directional_callchain_reachability', 'inline_memory_event',
           'semantic_event_plus_callchain', 'semantic_fusion', 'role_dangerous_call',
           'source_dependency_count', 'any_argument_dependency', 'cwe_checker_warning_count_adapter')


def read(path):
    with path.open(encoding='utf-8-sig',newline='') as handle:
        return list(csv.DictReader(handle))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def linux(path):
    value=Path(path).resolve().as_posix()
    return '/mnt/'+value[0].lower()+value[2:]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    args.out=args.out.resolve()
    args.out.mkdir(parents=True,exist_ok=False)
    artifacts=json.loads(args.artifacts.read_text(encoding='utf-8'))
    if len(artifacts)!=2 or {r['project'] for r in artifacts}!={'expat'}:
        raise ValueError('expected two declared published Expat conditions')
    config=REV/'address_model/config_semantic_v0_5.json'
    dangerous=PROJECT/'experiments/legacy/configs/dangerous_functions.csv'
    sources=PROJECT/'experiments/legacy/configs/input_sources.csv'
    frozen_files=[Path(__file__),REV/'fixed_budget.py',REV/'address_model/score.py',
                  REV/'address_model/ghidra_scripts/ExportAddressFacts.java',
                  REV/'argument_roles/ghidra_scripts/ExportArgumentRoles.java',
                  REV/'argument_roles/score_roles.py',REV/'argument_roles/schema.py',
                  config,dangerous,sources,args.artifacts,HERE/'baselines/adapt_cwe_checker_warnings.py',
                  HERE/'prepare_distribution_expat.py',HERE/'validation/expat_getbuffer.py']
    freeze={'created_utc':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
            'code_and_config_sha256':{str(p.resolve()):sha(p) for p in frozen_files},
            'artifacts':artifacts,'candidate_policy':'all recovered internal executable bodies; never filter on target or decompilation success',
            'role_interpretation':'intraprocedural ABI parameter dependency, not external-input taint or vulnerability detection',
            'selection_policy':'supplemental published-binary acquisition on the already selected Expat project; unchanged methods and weights; not an independent project',
            'budget_unit':'candidate count only; elapsed analyzer time separately recorded; no manual-effort claim',
            'external_timeout':420,'external_memory':'4g','external_cpus':2,'external_network':'none',
            'methods':METHODS,
            'acquisition_policy':'published ELF only; public source exists; no source used for scoring',
            'ghidra_analysis_timeout':240,'ghidra_outer_timeout':1800,
            'external_warning_policy':'warning-count ranking is an explicit adapter; native family hits retained separately',
            'failure_policy':'all declared conditions retained; incomplete score arrays fail; missing targets remain zero hits',
            'claim_gate':'new-project target retrieval only; independent reviewer unavailable; no novelty verdict'}
    dump(args.out/'freeze.json',freeze)
    image_check=subprocess.run(['docker','image','inspect',IMAGE],capture_output=True,timeout=45)
    (args.out/'docker_image.json').write_bytes(image_check.stdout or image_check.stderr)
    ledger=[]
    all_metrics=[]
    mappings=[]
    for artifact in artifacts:
        run=f"{artifact['project']}_{artifact['version']}_{artifact['condition']}"
        case=args.out/run
        case.mkdir()
        binary=Path(artifact['binary']).resolve()
        if sha(binary)!=artifact['sha256']: raise ValueError('binary changed after freeze')
        record={**artifact,'case_id':run,'status':'running','commands':[]}
        ledger.append(record)
        def save(): dump(args.out/'run_ledger.json',ledger)
        def local(command,log,timeout=1800):
            start=time.monotonic()
            done=None
            timed_out=False
            try:
                with (case/log).open('wb') as handle:
                    done=subprocess.run(command,stdout=handle,stderr=subprocess.STDOUT,timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                raise
            finally:
                record['commands'].append({'command':command,'returncode':done.returncode if done else None,
                    'timeout':timed_out,'seconds':time.monotonic()-start,'log':str(case/log)})
                save()
            if done.returncode: raise RuntimeError(str(case/log))
        try:
            print('EXTRACT',run,flush=True)
            projects=case/'ghidra_projects'; projects.mkdir()
            local(['wsl','-d','Ubuntu-24.04','--exec',
                   '/home/voidex/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless',linux(projects),run,
                   '-import',linux(binary),'-scriptPath',linux(REV/'address_model/ghidra_scripts')+';'+linux(REV/'argument_roles/ghidra_scripts'),
                   '-postScript','ExportAddressFacts.java',linux(case/'facts'),run,
                   '-postScript','ExportArgumentRoles.java',linux(case/'roles'),run,
                   '-analysisTimeoutPerFile','240','-deleteProject'],'ghidra.log')
            for folder in ('facts','roles'):
                meta=read(case/folder/'metadata.csv')[0]
                if meta['executable_sha256']!=artifact['sha256']: raise ValueError('export binary hash mismatch')
            start=time.monotonic()
            old=structural.score_features(case/'facts',structural.load_config(config),dangerous,sources)
            structural.write_outputs(case/'structural_scores',old)
            role=score_roles(case/'roles/argument_roles.csv',case/'roles/decompilation.csv')
            write_roles(case/'role_scores',role,case/'roles/argument_roles.csv',case/'roles/decompilation.csv',.25,3)
            record['scoring_seconds']=time.monotonic()-start
            population=[r['function'] for r in old['population']]
            if set(population)!={r['function_id'] for r in role['population']}: raise ValueError('role/structural populations differ')
            methods={'structural_v05':{r['function_id']:r['risk'] for r in old['function_scores']},
                     'argument_role_v02':{r['function_id']:r['risk'] for r in role['function_scores']},
                     'random_uniform':dict.fromkeys(population,0)}
            for row in old['baseline_function_scores']:
                methods.setdefault(row['baseline'],{})[row['function_id']]=row['risk']
            for row in role['baseline_function_scores']:
                name='role_dangerous_call' if row['baseline']=='dangerous_call' else row['baseline']
                methods.setdefault(name,{})[row['function_id']]=row['risk']
            any_dep={r['function_id']:0 for r in role['function_scores']}
            for row in read(case/'roles/argument_roles.csv'):
                if row['caller_id'] in any_dep and row['is_dangerous']=='true' and row['dependency_status'] in ('source','unresolved','truncated'):
                    any_dep[row['caller_id']]=1
            methods['any_argument_dependency']=any_dep
            # Scoring has completed before the target sidecar is read.
            cve,symbol,families=TARGETS[artifact['project']]
            functions=read(case/'facts/functions.csv')
            # Ground truth is consulted only here, after all local scores.
            with binary.open('rb') as handle:
                elf=ELFFile(handle); symbols=defaultdict(set)
                for sym in elf.get_section_by_name('.dynsym').iter_symbols():
                    if sym['st_info']['type']=='STT_FUNC' and sym['st_value'] and sym.name:
                        symbols[sym.name].add((sym['st_value'],sym['st_size']))
            if len(symbols.get(symbol,set()))!=1: raise ValueError('missing/ambiguous dynamic target')
            target_entry,target_size=next(iter(symbols[symbol]))
            if not target_size: raise ValueError('target dynamic symbol has no body size')
            anchors=Counter()
            for function in functions:
                values=symbols.get(function['name'],set())
                if function['name']!=symbol and len(values)==1 and function['function_id'] in population:
                    anchors[int(function['function_id'].split(':')[-1],16)-next(iter(values))[0]]+=1
            if not anchors or anchors.most_common(1)[0][1]<3:
                raise ValueError('insufficient independent ELF/Ghidra dynamic anchors')
            bias,agreement=anchors.most_common(1)[0]
            if agreement/sum(anchors.values())<.9: raise ValueError('inconsistent dynamic anchors')
            target=f"ram:{target_entry+bias:08x}"
            instructions=read(case/'facts/instructions.csv')
            witnessed=sum(r['caller_id']==target and target_entry<=int(r['address'].split(':')[-1],16)-bias<target_entry+target_size for r in instructions)
            if not witnessed: target=''
            mapping={**artifact,'case_id':run,'cve':cve,'target_symbol':symbol,'target_id':target,
                     'population':len(population),'target_in_population':target in population,
                     'mapping_policy':'post-scoring dynamic symbol; independent non-target dynamic anchors; instruction range witness',
                     'mapping_kind':'exported_function_body','containing_function':symbol,
                     'ghidra_elf_bias':bias,'target_instruction_witnesses':witnessed,
                     'anchor_agreement':agreement,'anchor_total':sum(anchors.values())}
            mappings.append(mapping)
            _write_csv(args.out/'target_mapping.csv',mappings)
            extname='cwe_checker_warning_count_adapter'
            failures=[]
            methods[extname]={}
            ext={'status':'unavailable','error':'pinned image not available','raw_warning_count':None}
            if image_check.returncode==0:
                name='paper-holdout-'+uuid.uuid4().hex[:12]
                output=case/'external'; output.mkdir()
                raw=output/'result.json'
                command=['docker','run','--name',name,'--rm','--pull=never','--network=none',
                         '--memory=4g','--memory-swap=5g','--cpus=2',
                         '-v',f'{binary}:/input/binary:ro','-v',f'{output}:/output',IMAGE,
                         '--json','--quiet','--out','/output/result.json','/input/binary']
                print('EXTERNAL',run,flush=True)
                start=time.monotonic()
                try:
                    local(command,'external.log',420)
                    payload=json.loads(raw.read_text(encoding='utf-8'))
                    if not isinstance(payload,list): raise ValueError('invalid warning array')
                    instructions=read(case/'facts/instructions.csv')
                    addresses={address_key(r['address']):r['caller_id'] for r in instructions}
                    counts,_,_,unmapped=map_warnings(payload,addresses,set(population))
                    matched,_,_,_=map_warnings(payload,addresses,set(population),families)
                    methods[extname]={f:counts[f] for f in population}
                    ext={'status':'ok','raw_warning_count':len(payload),'raw_sha256':sha(raw),
                         'target_warning_count':counts[target],'matched_target_warning_count':matched[target],
                         'unmapped_addresses':len(unmapped)}
                except subprocess.TimeoutExpired:
                    subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30)
                    ext={'status':'timeout','error':'420 seconds','raw_warning_count':None}
                except Exception as exc:
                    ext={'status':'analysis_failure','error':str(exc),'raw_warning_count':None}
                ext['seconds']=time.monotonic()-start
            record['external']=ext
            if ext['status']!='ok': failures.append({'case_id':run,'method':extname,'status':ext['status'],'error':ext['error']})
            if set(methods)!=set(METHODS): raise ValueError('method roster differs from freeze')
            metric=evaluate_by_case({m:{run:s} for m,s in methods.items()}, {run:target} if target else {},{run:population},failures)
            for row in metric: row.update({k:mapping[k] for k in ('project','version','condition','label','cve','target_symbol')})
            _write_csv(case/'metrics.csv',metric)
            _write_csv(case/'method_scores.csv',[{'method':m,'function_id':f,'score':s} for m,scores in methods.items() for f,s in scores.items()])
            all_metrics+=metric
            record.update(status='evaluated',population=len(population),target_id=target,
                          decompilation_failures=len(role['failures']))
            record['output_sha256']={str(p.relative_to(case)):sha(p) for folder in ('facts','roles','structural_scores','role_scores') for p in (case/folder).glob('*.csv')}
        except Exception as exc:
            record.update(status='analysis_failure',error=str(exc))
            for method in METHODS:
                all_metrics.append({**_empty_metrics(None,0,'analysis_failure',str(exc)),
                                    'case_id':run,'method':method,'target':'',
                                    **{k:artifact[k] for k in ('project','version','condition','label')},
                                    'cve':TARGETS[artifact['project']][0],
                                    'target_symbol':TARGETS[artifact['project']][1]})
        save()
        if all_metrics: _write_csv(args.out/'per_condition.csv',all_metrics)
        print('DONE',run,record['status'],flush=True)
    # All declared artifacts remain in ledger; failures lacking a candidate
    # pool cannot be mistaken for a smaller denominator.
    changed=[p for p,digest in freeze['code_and_config_sha256'].items() if sha(Path(p))!=digest]
    dump(args.out/'completion.json',{'conditions':len(ledger),'evaluated':sum(r['status']=='evaluated' for r in ledger),
                                     'failed':sum(r['status']!='evaluated' for r in ledger),'changed_frozen_files':changed,
                                     'no_independent_review':True})
    if changed: raise ValueError('frozen files changed during experiment')


if __name__=='__main__': main()
