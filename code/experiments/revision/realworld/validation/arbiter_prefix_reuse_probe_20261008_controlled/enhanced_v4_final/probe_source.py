"""Controlled runtime fingerprints; not a proof of semantic state equivalence.

Earlier results/sources remain unchanged. All positive gates require nonempty
evidence. State identity uses explicit, pinned-runtime projections rather than
pickling whole angr plugins, whose object graphs include unstable lifecycle
details. Projection omissions remain outside the mechanism claim.
"""
from __future__ import annotations
import copy
import inspect
import json
import os
import re
import subprocess
import time
from pathlib import Path
import angr
import claripy
import cle
import pyvex
import arbiter_prefix_reuse_strict_probe_20261008 as base
from arbiter.master_chief import SymExec

SCHEMA = 'prefix-runtime-fingerprint-v4'
sha256_bytes, sha256_file = base.sha256_bytes, base.sha256_file


def canonical(value):
    if isinstance(value, bytes):
        return {'bytes_hex': value.hex()}
    if isinstance(value, dict):
        return {str(k): canonical(v) for k, v in sorted(value.items(), key=lambda x: str(x[0]))}
    if isinstance(value, (tuple, list)):
        return [canonical(x) for x in value]  # preserve semantically relevant order
    if isinstance(value, (set, frozenset)):
        return sorted((canonical(x) for x in value), key=repr)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError('Unrepresentable exploration argument')


def digest_projection(value):
    return sha256_bytes(json.dumps(canonical(value), sort_keys=True, separators=(',', ':')).encode())


def project_identity(project):
    objects, hooks = [], []
    for obj in project.loader.all_objects:
        path = Path(obj.binary) if obj.binary else None
        file_backed = bool(path and path.is_file())
        virtual = type(obj).__module__.startswith(('cle.backends.externs', 'cle.backends.tls'))
        if not file_backed and not virtual:
            raise ValueError('Unrepresented loaded object')
        objects.append({
            'class': type(obj).__module__ + '.' + type(obj).__qualname__,
            'binary': str(obj.binary), 'kind': 'file' if file_backed else 'CLE_virtual',
            'binary_sha256': sha256_file(path) if file_backed else None,
            'mapped_base': obj.mapped_base, 'min_addr': obj.min_addr, 'max_addr': obj.max_addr,
            'backers': [{'offset': int(a), 'size': len(b), 'sha256': sha256_bytes(bytes(b))}
                        for a, b in obj.memory.backers()]})
    for addr, proc in sorted(project._sim_procedures.items()):
        hooks.append({'address': addr, 'class': type(proc).__module__ + '.' + type(proc).__qualname__,
                      'source_sha256': sha256_bytes(inspect.getsource(type(proc)).encode()),
                       'kwargs_sha256': digest_projection(proc.kwargs), 'num_args': proc.num_args,
                      'is_function': proc.is_function, 'library_name': proc.library_name})
    return {'loaded_objects': objects, 'hooks': hooks}


def _filesystem_projection(plugin):
    files = []
    for path, simfile in sorted(plugin._files.items(), key=lambda x: str(x[0])):
        if not type(simfile).__module__.startswith('angr.'):
            raise ValueError('Unsupported filesystem object')
        files.append({'path': str(path), 'class': type(simfile).__module__ + '.' + type(simfile).__qualname__,
                      'attrs': canonical({k: v for k, v in simfile.__dict__.items() if k != 'state'
                                           and isinstance(v, (str, int, float, bool, type(None), list, tuple, dict, set, frozenset))})})
    return {'cwd': plugin.cwd, 'pathsep': plugin.pathsep, 'files': files,
            'mountpoints': sorted(str(x) for x in plugin._mountpoints),
            'unlinks': sorted(str(x) for x in plugin._unlinks)}


def _posix_projection(plugin):
    scalar = {}
    for name in ('argc', 'argv', 'brk', 'gid', 'max_length', 'maximum_symbolic_syscalls', 'pid', 'ppid', 'sigmask_bits', 'uid'):
        value = getattr(plugin, name)
        try:
            scalar[name] = canonical(value)
        except TypeError:
            scalar[name] = str(value)
    descriptors = {}
    for name in ('stdin', 'stdout', 'stderr'):
        stream = getattr(plugin, name)
        if not type(stream).__module__.startswith('angr.'):
            raise ValueError('Unsupported POSIX stream')
        descriptors[name] = {'class': type(stream).__module__ + '.' + type(stream).__qualname__,
                             'attrs': canonical({k: v for k, v in stream.__dict__.items() if k != 'state'
                                                  and isinstance(v, (str, int, float, bool, type(None), list, tuple, dict, set, frozenset))})}
    return {'scalar': scalar, 'streams': descriptors,
            'fd_numbers': sorted(int(x) for x in plugin.fd),
            'closed_fds': sorted(int(x) for x in plugin._closed_fds)}


def _history_projection(plugin):
    return {'bbl_addrs': [int(x) for x in plugin.bbl_addrs],
            'recent_bbl_addrs': [int(x) for x in plugin.recent_bbl_addrs],
            'depth': plugin.depth, 'jump_source': plugin.jump_source,
            'jump_target': plugin.jump_target, 'jumpkind': plugin.jumpkind,
            'recent_description': plugin.recent_description}


def _globals_projection(plugin):
    return canonical(plugin._backer)


def state_identity(state):
    descriptor = base.state_descriptor(state)
    supported = {
        'fs': _filesystem_projection,
        'globals': _globals_projection,
        'history': _history_projection,
        'posix': _posix_projection,
    }
    plugins = []
    for name, plugin in sorted(state.plugins.items()):
        qualified = type(plugin).__module__ + '.' + type(plugin).__qualname__
        if not type(plugin).__module__.startswith('angr.'):
            raise ValueError('Unsupported plugin class')
        entry = {'name': name, 'class': qualified}
        if name in supported:
            entry['projection_sha256'] = digest_projection(supported[name](plugin))
        elif name in {'memory', 'registers', 'regs', 'scratch', 'solver'}:
            # Memory/register pages, solver constraints, and the initial
            # execution location are projected by state_descriptor. This
            # controlled probe does not claim a complete plugin equivalence.
            entry['projection'] = 'covered_by_state_descriptor'
        else:
            raise ValueError('Unsupported default plugin: ' + name)
        plugins.append(entry)
    return {'descriptor': descriptor, 'plugins': plugins}


def clone_state(state):
    cloned = state.copy()
    if 'globals' in state.plugins:
        for key, value in state.globals.items():
            cloned.globals[key] = copy.deepcopy(value)
    return cloned


def counters():
    return {'prefix_executions': 0, 'prefix_cache_hits': 0, 'continuation_executions': 0,
            'admission_attempts': 0, 'admitted_results': 0, 'rejected_admissions': 0,
            'termination_events': [], 'requests': []}


def context(binary):
    return {'binary_sha256': sha256_file(binary),
            'arbiter_source_sha256': sha256_bytes(inspect.getsource(SymExec.verify_one).encode()),
            'dependencies': {m.__name__: getattr(m, '__version__', 'unknown') for m in (angr, claripy, cle, pyvex)},
            'unknown_alias': False, 'partial_timeout': False, 'timeout_budget_s': 30.0,
            'identity_scope': 'pinned-runtime observable fingerprint, not exhaustive semantic identity'}


class EnhancedPrefixProxy(base.StrictPrefixProxy):
    def __init__(self, manager, cache, counts, ctx, enabled, project, timeout_observer=lambda: None):
        super().__init__(manager, cache, counts, ctx, enabled)
        self._project, self._timeout_observer = project, timeout_observer

    def _key(self, args, kwargs):
        for flag in ('unknown_alias', 'partial_timeout'):
            if self._context[flag]:
                return None, None, 'injected_' + flag
        if self._timeout_observer():
            return None, None, 'arbiter_timeout_flag'
        try:
            payload = {'schema': SCHEMA, 'context': dict(self._context),
                       'project': project_identity(self._project), 'args': canonical(args),
                       'kwargs': canonical(kwargs), 'states': [state_identity(s) for s in self._manager.active]}
            return sha256_bytes(json.dumps(payload, sort_keys=True).encode()), payload, None
        except (TypeError, ValueError, AttributeError, OSError) as exc:
            return None, None, 'identity_unavailable:' + type(exc).__name__ + ':' + str(exc)

    def _event(self, kind, elapsed, returned, error=None):
        stashes = {n: len(s) for n, s in self._manager.stashes.items()}
        found, active, errored = stashes.get('found', 0), stashes.get('active', 0), len(self._manager.errored)
        timeout = self._timeout_observer()
        if error:
            status = 'interrupted' if error == 'KeyboardInterrupt' else 'error'
        elif not returned:
            status = 'unknown'
        elif timeout or elapsed > self._context['timeout_budget_s']:
            status = 'timeout_observed'
        elif self._context['partial_timeout']:
            status = 'injected_partial_timeout'
        elif errored:
            status = 'errored_states'
        elif active or any(v for n, v in stashes.items() if n not in {'found', 'avoid', 'deadended', 'unsat', 'pruned'}):
            status = 'partial_frontier'
        elif found:
            status = 'reached_stop'  # no claim of exhaustive path enumeration
        else:
            status = 'empty'
        return {'kind': kind, 'status': status, 'elapsed_s': elapsed, 'returned_normally': returned,
                'error': error, 'stashes': stashes, 'found': found, 'active': active, 'errored': errored,
                'arbiter_timeout_received': timeout, 'admitted': False}

    def explore(self, *args, **kwargs):
        prefix = 'avoid' in kwargs
        key, payload, reason = None, None, 'disabled'
        if prefix and self._enabled:
            key, payload, reason = self._key(args, kwargs)
            self._counters['admission_attempts' if key is not None else 'rejected_admissions'] += 1
        if prefix:
            self._counters['requests'].append({'key': key, 'refusal': reason, 'cache_size_before': len(self._cache)})
        if prefix and key is not None and key in self._cache and self._cache[key]['payload'] == payload:
            self._manager.stashes.clear()
            self._manager.stashes.update({n: [clone_state(s) for s in states]
                                         for n, states in self._cache[key]['stashes'].items()})
            self._counters['prefix_cache_hits'] += 1
            event = self._event('prefix_cache_hit', 0.0, True)
            event['key'] = key
            self._counters['termination_events'].append(event)
            return self
        self._counters['prefix_executions' if prefix else 'continuation_executions'] += 1
        start, returned, error = time.monotonic(), False, None
        try:
            self._manager.explore(*args, **kwargs)
            returned = True
        except BaseException as exc:
            error = type(exc).__name__
            raise
        finally:
            event = self._event('prefix_execution' if prefix else 'continuation', time.monotonic() - start, returned, error)
            event.update(key=key, refusal=reason)
            if prefix and self._enabled and key is not None and event['status'] == 'reached_stop':
                self._cache[key] = {'payload': payload,
                                    'stashes': {n: [clone_state(s) for s in states]
                                                for n, states in self._manager.stashes.items()}}
                event['admitted'] = True
                self._counters['admitted_results'] += 1
            self._counters['termination_events'].append(event)
        return self


def install_enhanced_cache(symexec, binary_sha256, enabled, context_overrides=None):
    project = symexec._project
    original, cache, counts = project.factory.simulation_manager, {}, counters()
    ctx = context(Path(project.filename))
    if context_overrides:
        ctx.update(context_overrides)
    def wrapped(state=None, *args, **kwargs):
        return EnhancedPrefixProxy(original(state, *args, **kwargs), cache, counts, ctx, enabled,
                                   project, lambda: getattr(symexec, '_timeout_received', None))
    project.factory.simulation_manager = wrapped
    return counts, ctx


def run_arm(binary, enabled):
    original = base.install_strict_cache
    try:
        base.install_strict_cache = install_enhanced_cache
        return base.run_arm(binary, enabled)
    finally:
        base.install_strict_cache = original


def concrete_execution_check(binary):
    runs = []
    for extra in (0, 1, 4):
        command = [str(binary)] + ['fixture_arg'] * extra
        proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
        expected = 3 * (1 + extra) + 36  # arithmetic from the independent C specification
        runs.append({'command': command, 'returncode': proc.returncode, 'stdout': proc.stdout,
                     'stderr': proc.stderr, 'expected': expected, 'passed': proc.returncode == expected})
    command = ['objdump', '-d', str(binary)]
    dump = subprocess.run(command, capture_output=True, text=True, timeout=10)
    block = re.search(r'^[0-9a-f]+ <shared_prefix>:\n(.*?)(?=\n\n|\Z)', dump.stdout, re.M | re.S)
    calls = re.findall(r'^\s*([0-9a-f]+):.*\bcall\w*\s+.*<target_sink>', block[1], re.M) if block else []
    return {'runs': runs, 'inventory_command': command, 'inventory_returncode': dump.returncode,
            'inventory_stdout': dump.stdout, 'inventory_stderr': dump.stderr, 'target_sink_calls': calls,
            'passed': all(r['passed'] for r in runs) and dump.returncode == 0 and len(calls) == 3,
            'scope': 'concrete arithmetic and call inventory, not a defect oracle'}


class ControlHook(angr.SimProcedure):
    def run(self):
        return 0


def lifecycle_control(binary, case):
    """Prefill, unchanged hit and actual mutation in ONE cache lifecycle."""
    project = angr.Project(str(binary), auto_load_libs=False)
    start, target = [project.loader.find_symbol(n).rebased_addr for n in ('driver', 'shared_prefix')]
    cache, counts, ctx, changed, timeout_flag = {}, counters(), context(binary), False, False
    # The first blank state initializes angr's global defaults. It is not a
    # candidate request and prevents this one-time initialization from posing as
    # a state-identity change in the prefill/hit control.
    project.factory.blank_state(addr=start)
    def invoke():
        state = project.factory.blank_state(addr=start)
        state.globals['probe'] = {'values': [0]}
        if changed and case == 'plugin_mutation':
            state.globals['probe']['values'].append(1)
        if changed and case == 'register_mutation':
            state.regs.r12 = 7
        if changed and case == 'state_memory_mutation':
            state.memory.store(0x20000000, b'control')
        if changed and case == 'constraint_mutation':
            state.solver.add(claripy.BVS('control', 8, explicit_name=True) == 7)
        manager = project.factory.simulation_manager(state)
        proxy = EnhancedPrefixProxy(manager, cache, counts, ctx, True, project, lambda: timeout_flag)
        before = {k: counts[k] for k in ('prefix_executions', 'prefix_cache_hits', 'admitted_results', 'rejected_admissions')}
        request = {'find': target, 'avoid': []}
        if changed and case == 'partial_frontier':
            request['n'] = 0  # actual exploration returns without stepping
        if changed and case in {'interrupt', 'error'}:
            def failed(*args, **kwargs):
                if case == 'interrupt':
                    raise KeyboardInterrupt('controlled interruption')
                raise RuntimeError('controlled engine failure')
            manager.explore, request['n'] = failed, 1
        caught = None
        try:
            chained = proxy.explore(**request) is proxy
        except (KeyboardInterrupt, RuntimeError) as exc:
            caught, chained = type(exc).__name__, None
        return {'delta': {k: counts[k] - before[k] for k in before},
                'event': dict(counts['termination_events'][-1]), 'request': counts['requests'][-1],
                'chained_proxy': chained, 'caught': caught}
    prefill, unchanged = invoke(), invoke()
    changed = True
    if case == 'hook_mutation':
        project.hook(0x30000000, ControlHook())
    elif case == 'loaded_memory_mutation':
        obj = project.loader.main_object
        addr, data = next(obj.memory.backers())
        obj.memory.store(addr, bytes([data[0] ^ 1]))  # header byte, outside executed prefix
    elif case in {'unknown_alias', 'partial_timeout'}:
        ctx[case] = True
    elif case == 'timeout_flag':
        timeout_flag = True
    elif case == 'elapsed_budget':
        ctx['timeout_budget_s'] = 0.0
    mutation = invoke()
    prerequisites = prefill['delta']['admitted_results'] == 1 and unchanged['delta']['prefix_cache_hits'] == 1
    separation = mutation['delta']['prefix_cache_hits'] == 0 and mutation['delta']['prefix_executions'] == 1
    refusal = case in {'unknown_alias', 'partial_timeout', 'timeout_flag', 'elapsed_budget', 'partial_frontier', 'interrupt', 'error'}
    passed = prerequisites and separation and mutation['delta']['admitted_results'] == (0 if refusal else 1)
    return {'case': case, 'kind': 'refusal' if refusal else 'key_separation', 'prefill': prefill,
            'unchanged': unchanged, 'mutation': mutation, 'passed': passed,
            'scope': 'same-cache controlled mutation; alias/timeout/exception controls are injections'}


def clone_control(binary):
    project = angr.Project(str(binary), auto_load_libs=False)
    frozen = project.factory.blank_state(addr=project.entry)
    frozen.globals['sym_vars'] = {'nested': [1]}
    frozen.memory.store(0x20000000, b'A')
    frozen.regs.r12 = 1
    first, second = clone_state(frozen), clone_state(frozen)
    first.globals['sym_vars']['nested'].append(2)
    first.memory.store(0x20000000, b'B')
    first.regs.r12 = 2
    checks = {'nested_globals': frozen.globals['sym_vars'] == second.globals['sym_vars'] == {'nested': [1]},
              'memory': all(s.solver.eval(s.memory.load(0x20000000, 1)) == 65 for s in (frozen, second)),
              'register': all(s.solver.eval(s.regs.r12) == 1 for s in (frozen, second))}
    return {'checks': checks, 'passed': all(checks.values()), 'scope': 'tested globals, memory and registers only'}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=2)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error('positive repetition count required')
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'probe_source.py').write_bytes(Path(__file__).read_bytes())
    cases = ('hook_mutation', 'loaded_memory_mutation', 'plugin_mutation', 'register_mutation',
             'state_memory_mutation', 'constraint_mutation', 'unknown_alias', 'partial_timeout',
             'timeout_flag', 'elapsed_budget', 'partial_frontier', 'interrupt', 'error')
    runs = []
    for i in range(args.repetitions):
        baseline, reuse = run_arm(args.binary, False), run_arm(args.binary, True)
        b, r = baseline['counters'], reuse['counters']
        runs.append({'repetition': i + 1, 'baseline': baseline, 'reuse': reuse,
                     'same_nonempty_report_signature': bool(baseline['report_signature']) and baseline['report_signature'] == reuse['report_signature'],
                     'positive_reuse': b['prefix_executions'] == 3 and b['admitted_results'] == 0 and r['prefix_executions'] == 1 and r['prefix_cache_hits'] == 2 and r['admitted_results'] == 1,
                     'admission_status_gate': r['admitted_results'] > 0 and all(e['status'] == 'reached_stop' for e in r['termination_events'] if e['admitted'])})
    result = {'fixture': str(args.binary), 'binary_sha256': sha256_file(args.binary),
              'source_sha256': sha256_file(Path(__file__)), 'base_source_sha256': sha256_file(Path(base.__file__)),
              'image_digest': os.environ.get('ARBITER_IMAGE_DIGEST', 'unrecorded'), 'schema': SCHEMA,
              'runs': runs, 'control_matrix': [lifecycle_control(args.binary, c) for c in cases],
              'clone_control': clone_control(args.binary), 'concrete_execution': concrete_execution_check(args.binary),
              'claim_boundary': 'controlled fingerprint mechanism only; no semantic equivalence, defect or timing claim'}
    result['gates'] = {'nonempty_signatures': all(r['same_nonempty_report_signature'] for r in runs),
                       'positive_reuse': all(r['positive_reuse'] for r in runs),
                       'admission_status': all(r['admission_status_gate'] for r in runs),
                       'lifecycle_controls': all(r['passed'] for r in result['control_matrix']),
                       'clone_isolation': result['clone_control']['passed'],
                       'concrete_execution': result['concrete_execution']['passed']}
    result['all_gates_passed'] = all(result['gates'].values())
    (args.out / 'results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result['gates']))
    if not result['all_gates_passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
