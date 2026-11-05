"""Private NumPyro validation controller; execution requires packet approval."""
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

P = Path('/inputs')
W = Path('/work')
E = W / 'evidence'
E.mkdir(parents=True, exist_ok=True)
M = json.loads((P / 'manifest.json').read_text())
ROWS = json.loads((P / 'commands.json').read_text())
ORIGIN = int(os.environ['PACKET_ORIGIN'])
DEADLINE = ORIGIN + M['deadline_seconds'] - 150
BASE_ENV = dict(os.environ, HOME='/work/home', UV_CACHE_DIR='/work/uv-cache',
                PREK_HOME='/work/prek-cache', PYTEST_ADDOPTS='', PYTHONPATH='', CI='true')
UV = [sys.executable, '-m', 'uv']
PY = '/work/venv/bin/python'


def terminated(signum, frame):
    raise SystemExit(143)


signal.signal(signal.SIGTERM, terminated)


def save(name, value):
    (E / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(name, argv, cwd=W, env=None, seconds=600, expected=(0,)):
    """Retain both streams and status even when the deadline or command fails."""
    limit = min(seconds, DEADLINE - time.time())
    if limit <= 0:
        save(name, {'argv': argv, 'state': 'DEADLINE_BEFORE_START'})
        raise RuntimeError('WHOLE_PACKET_DEADLINE')
    start = time.monotonic()
    status = {'argv': argv, 'cwd': str(cwd), 'timeout': limit}
    actual_env = dict(env or BASE_ENV)
    if argv[:3] == UV:
        # Same successful bootstrap invocation as the retained closure run.
        actual_env['PYTHONPATH'] = '/work/tool'
    try:
        with (E / (name + '.stdout')).open('wb') as out, (E / (name + '.stderr')).open('wb') as err:
            p = subprocess.run(argv, cwd=cwd, env=actual_env, stdout=out,
                               stderr=err, timeout=limit)
        status['returncode'] = p.returncode
    except subprocess.TimeoutExpired:
        status['state'] = 'TIMEOUT'
        raise
    except BaseException as exc:
        status.update(state='INTERRUPTED', error=repr(exc))
        raise
    finally:
        status['seconds'] = time.monotonic() - start
        save(name, status)
    if p.returncode not in expected:
        raise RuntimeError(name + ': ' + str(p.returncode))
    return (E / (name + '.stdout')).read_text(errors='replace')


def guard(source, python=PY, baseline=False, installed=False):
    expected = M['baseline_util_sha256'] if baseline else M['util_sha256']
    code = '''import hashlib,importlib.metadata,json,pathlib,numpyro
p=pathlib.Path(numpyro.__file__).resolve();u=p.parent/'infer/util.py'
assert hashlib.sha256(u.read_bytes()).hexdigest()==EXPECTED
d=importlib.metadata.distribution('numpyro');raw=d.read_text('direct_url.json')
print(json.dumps({'file':str(p),'direct_url':raw,'version':d.version}))
if INSTALLED:
 assert 'site-packages' in str(p) and not str(p).startswith(SOURCE+'/')
else:
 assert str(p).startswith(SOURCE+'/')
 j=json.loads(raw); assert j['dir_info']['editable'] is True
 assert j['url']=='file://'+SOURCE
 assert len([x for x in importlib.metadata.distributions() if x.metadata['Name'].lower()=='numpyro'])==1
'''
    code = ('EXPECTED=' + repr(expected) + '\nSOURCE=' + repr(str(source)) +
            '\nINSTALLED=' + repr(installed) + '\n' + code)
    run('guard-' + ('wheel' if installed else source.name), [python, '-c', code], cwd=W)


def source_invariant(source, label):
    head = run(label + '-head', ['git', 'rev-parse', 'HEAD'], cwd=source).strip()
    assert head == M['published']
    for path, expected in M['source_blobs'].items():
        blob = run(label + '-' + Path(path).stem, ['git', 'hash-object', path], cwd=source).strip()
        assert blob == expected, (path, blob, expected)
    status = run(label + '-status', ['git', 'status', '--porcelain', '--untracked-files=no'], cwd=source)
    assert {line[3:] for line in status.splitlines()} == set(M['source_blobs']), status
    run(label + '-diff', ['git', 'diff', '--full-index'], cwd=source)


def pytest(name, args, source, env=None, python=PY, workers=0, expected=(0,)):
    e = dict(BASE_ENV, PATH=str(Path(python).parent) + ':' + BASE_ENV['PATH'])
    e.update(env or {})
    e['PYTHONPATH'] = str(W)
    xml = E / (name + '.xml')
    argv = [python, '-m', 'pytest', '-p', 'node_recorder', '-vs', '--durations=100', '--junitxml=' + str(xml)]
    if workers:
        argv += ['-n', str(workers), '--dist=load']
    argv += args
    run(name, argv, cwd=source, env=e, seconds=3000, expected=expected)
    root = ET.parse(xml).getroot()
    cases = list(root.iter('testcase'))
    result = {'total': len(cases), 'failed': sum(x.find('failure') is not None for x in cases),
              'errors': sum(x.find('error') is not None for x in cases),
              'skipped': sum(x.find('skipped') is not None for x in cases)}
    result['passed'] = result['total'] - result['failed'] - result['errors'] - result['skipped']
    save(name + '-counts', result)
    return result


def collection(name, args, env, source):
    # Same real pytest collection and environment as the execution command.
    output = E / (name + '-ids.json')
    plugin = W / 'collection_recorder.py'
    plugin.write_text('import json,os\nfrom pathlib import Path\n'
                      'def pytest_collection_finish(session):\n'
                      ' Path(os.environ["COLLECT_IDS"]).write_text(json.dumps([i.nodeid for i in session.items]))\n')
    e = dict(BASE_ENV, **env)
    e.update(PYTHONPATH=str(W), COLLECT_IDS=str(output))
    run('collect-' + name, [PY, '-m', 'pytest', '--collect-only', '-q', '-p',
        'collection_recorder'] + args, cwd=source, env=e, seconds=300)
    ids = json.loads(output.read_text())
    assert ids and len(ids) == len(set(ids)), name
    return set(ids)


def diagnose(name, source, env=None, python=PY, xml_path=None):
    """Bounded classification only; preserve every primary failure."""
    records = []
    try:
        xml = xml_path or E / (name + '.xml')
        if not xml.exists():
            records.append({'state': 'NO_JUNIT'})
            return
        for case in ET.parse(xml).iter('testcase'):
            if case.find('failure') is None and case.find('error') is None:
                continue
            if len(records) >= M['serial_diagnostic_max']:
                records.append({'state': 'LIMIT_REACHED'})
                break
            if DEADLINE - time.time() < 300:
                records.append({'state': 'INSUFFICIENT_TIME'})
                break
            ids = {x.attrib['value'] for x in case.findall('./properties/property')
                   if x.attrib['name'] == 'exact_nodeid'}
            if len(ids) != 1:
                records.append({'state': 'UNIDENTIFIED', 'classname': case.get('classname'),
                                'name': case.get('name')})
                continue
            node = ids.pop()
            try:
                r = pytest(name + '-serial-' + str(len(records)), [node], source,
                           env=env, python=python, expected=(0, 1))
                records.append({'node': node, 'counts': r,
                    'state': 'ORDER_DEPENDENT_UNDER_XDIST' if r['passed'] else 'FAILURE_REPRODUCED'})
            except BaseException as exc:
                records.append({'node': node, 'state': 'DIAGNOSTIC_ERROR', 'error': repr(exc)})
                if isinstance(exc, (SystemExit, KeyboardInterrupt)):
                    raise
    except BaseException as exc:
        records.append({'state': 'DIAGNOSTIC_ERROR', 'error': repr(exc)})
        if isinstance(exc, (SystemExit, KeyboardInterrupt)):
            raise
    finally:
        save(name + '-diagnostic-summary', records)


def prepare():
    assert platform.machine() == M['arch'] and platform.python_version() == M['python']
    for d in ('home', 'tool', 'uv-cache', 'fixture'):
        (W / d).mkdir(exist_ok=True)
    (W / 'node_recorder.py').write_text('import pytest\n'
        '@pytest.hookimpl(hookwrapper=True)\n'
        'def pytest_runtest_makereport(item,call):\n'
        ' report=(yield).get_result()\n'
        ' report.user_properties.append(("exact_nodeid",item.nodeid))\n')
    run('bootstrap', [sys.executable, '-m', 'pip', 'install', '--no-deps', '--require-hashes',
        '--target', '/work/tool', '-r', '/inputs/bootstrap.txt'], seconds=180)
    assert run('uv-version', UV + ['--version']).strip().startswith('uv 0.11.8')
    # Actual controller fixture before the expensive 200-package sync.
    run('fixture-streams', [sys.executable, '-c',
        'import sys;print("stdout-proof");print("stderr-proof",file=sys.stderr)'])
    assert 'stdout-proof' in (E / 'fixture-streams.stdout').read_text()
    assert 'stderr-proof' in (E / 'fixture-streams.stderr').read_text()
    try:
        run('fixture-timeout', [sys.executable, '-c', 'import time;time.sleep(3)'], seconds=0.1)
    except subprocess.TimeoutExpired:
        assert json.loads((E / 'fixture-timeout.json').read_text())['state'] == 'TIMEOUT'
    else:
        raise AssertionError('fixture timeout not exercised')
    # One tiny real pytest-xdist environment, no scientific imports.
    run('fixture-venv', UV + ['venv', '/work/fixture-env', '--python', sys.executable])
    run('fixture-tools', UV + ['pip', 'install', '--python', '/work/fixture-env/bin/python',
        '--no-deps', '--require-hashes', '-r', '/inputs/fixture-tools.txt'], seconds=180)
    (W / 'fixture/test_fixture.py').write_text('def test_one():\n assert 1 == 1\n\ndef test_two():\n assert 2 == 2\n')
    r = pytest('fixture-xdist', [], W / 'fixture', python='/work/fixture-env/bin/python', workers=2)
    assert r == {'total': 2, 'failed': 0, 'errors': 0, 'skipped': 0, 'passed': 2}
    (W / 'fixture/test_negative.py').write_text('import pytest\n'
        'def test_expected_failure():\n assert False\n'
        '@pytest.fixture\ndef broken():\n raise RuntimeError("intentional setup error")\n'
        'def test_setup_error(broken):\n pass\n')
    r = pytest('fixture-negative', ['test_negative.py'], W / 'fixture',
        python='/work/fixture-env/bin/python', workers=2, expected=(1,))
    assert r['failed'] == 1 and r['errors'] == 1
    fixture_xml = ET.parse(E / 'fixture-negative.xml')
    missing = ET.SubElement(fixture_xml.getroot(), 'testcase', classname='worker', name='crash')
    ET.SubElement(missing, 'error').text = 'synthetic worker-crash identity fixture'
    fixture_xml.write(E / 'fixture-diagnostics.xml')
    diagnose('fixture-negative', W / 'fixture', python='/work/fixture-env/bin/python',
             xml_path=E / 'fixture-diagnostics.xml')
    diagnostic = json.loads((E / 'fixture-negative-diagnostic-summary.json').read_text())
    assert len([r for r in diagnostic if r['state'] == 'FAILURE_REPRODUCED']) == 2
    assert len([r for r in diagnostic if r['state'] == 'UNIDENTIFIED']) == 1
    build_fixture = W / 'build-fixture'
    build_fixture.mkdir()
    (build_fixture / 'fixture_backend.py').write_text('VALUE = 1\n')
    (build_fixture / 'pyproject.toml').write_text('[build-system]\n'
        'requires=["setuptools>=77","wheel"]\nbuild-backend="setuptools.build_meta"\n'
        '[project]\nname="backend-fixture"\nversion="0.0.1"\n'
        '[tool.setuptools]\npy-modules=["fixture_backend"]\n')
    run('build-fixture-init', ['git', 'init', '--quiet', str(build_fixture)])
    run('build-fixture-add', ['git', '-C', str(build_fixture), 'add', '.'])
    run('build-fixture-commit', ['git', '-C', str(build_fixture), '-c', 'user.name=Fixture',
        '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'fixture'])
    fixture_sha = run('build-fixture-sha', ['git', '-C', str(build_fixture), 'rev-parse', 'HEAD']).strip()
    (W / 'fixture-build.txt').write_text('backend-fixture @ git+file:///work/build-fixture@' + fixture_sha + '\n')
    run('build-fixture-sync', UV + ['-v', 'pip', 'sync', '--python', '/work/fixture-env/bin/python',
        '--build-constraints', '/inputs/build-constraints.txt', '/work/fixture-build.txt'], seconds=180)
    build_log = (E / 'build-fixture-sync.stderr').read_text()
    assert '80.9.0' in build_log and '0.45.1' in build_log, 'BUILD_BACKEND_PINS_NOT_OBSERVED'
    save('build-backend-fixture', {'setuptools': '80.9.0', 'wheel': '0.45.1',
        'log': 'build-fixture-sync.stderr', 'hashes': M['backend_metadata_hashes'],
        'note': 'Versions constrained; isolated backend acquisition recorded in verbose uv log. This is not --require-hashes enforcement for VCS builds.'})
    source = W / 'candidate'
    run('source-init', ['git', 'init', '--quiet', str(source)])
    run('source-fetch', ['git', '-C', str(source), 'fetch', '--depth=1',
        M['source_url'], M['published']], seconds=90)
    run('source-checkout', ['git', '-C', str(source), 'checkout', '--detach', '--quiet', 'FETCH_HEAD'])
    run('source-apply-check', ['git', '-C', str(source), 'apply', '--check', '/inputs/repair.patch'])
    run('source-apply', ['git', '-C', str(source), 'apply', '/inputs/repair.patch'])
    source_invariant(source, 'after-apply')
    run('venv', UV + ['venv', '/work/venv', '--python', sys.executable])
    t = time.monotonic()
    # Explicit fresh authorization is required for this previously attempted prerequisite.
    run('sync', UV + ['-v', 'pip', 'sync', '--python', PY, '--build-constraints',
        '/inputs/build-constraints.txt', '/inputs/closure.txt'], seconds=600)
    run('freeze-before-overlay', UV + ['pip', 'freeze', '--python', PY])
    run('overlay', UV + ['pip', 'install', '--python', PY, '--no-deps', '--require-hashes',
        '-r', '/inputs/overlay.txt'], seconds=180)
    run('source-editable', UV + ['pip', 'install', '--python', PY, '--no-deps',
        '--no-build-isolation', '--editable', str(source)])
    run('pip-check', UV + ['pip', 'check', '--python', PY])
    run('freeze-after-overlay', UV + ['pip', 'freeze', '--python', PY])
    save('setup-price', {'install_seconds': time.monotonic() - t,
                        'whole_job_overhead_seconds': time.time() - ORIGIN})
    guard(source)
    return source


def d0(source):
    repair_args = ['test/infer/test_infer_util.py', 'test/infer/test_autoguide.py',
                   '-k', ' or '.join(M['repair_names'])]
    baseline = W / 'baseline'
    run('baseline-clone', ['git', 'clone', '--local', '--no-hardlinks', str(source), str(baseline)])
    # Copy only the candidate tests: util remains the published c4 implementation.
    for f in ('test/infer/test_infer_util.py', 'test/infer/test_autoguide.py'):
        (baseline / f).write_bytes((source / f).read_bytes())
    bp = '/work/baseline-env/bin/python'
    run('baseline-venv', UV + ['venv', '/work/baseline-env', '--python', sys.executable])
    run('baseline-sync', UV + ['-v', 'pip', 'sync', '--python', bp, '--build-constraints',
        '/inputs/build-constraints.txt', '/inputs/closure.txt'], seconds=300)
    run('baseline-overlay', UV + ['pip', 'install', '--python', bp, '--no-deps',
        '--require-hashes', '-r', '/inputs/overlay.txt'])
    run('baseline-editable', UV + ['pip', 'install', '--python', bp, '--no-deps',
        '--no-build-isolation', '--editable', str(baseline)])
    guard(baseline, python=bp, baseline=True)
    b = pytest('baseline-new-tests', repair_args, baseline, python=bp, expected=(1,))
    assert b['failed'] == 5 and b['passed'] == 14 and b['errors'] == b['skipped'] == 0
    failed_ids = set()
    for case in ET.parse(E / 'baseline-new-tests.xml').iter('testcase'):
        if case.find('failure') is not None:
            failed_ids.update(x.attrib['value'] for x in case.findall('./properties/property')
                              if x.attrib['name'] == 'exact_nodeid')
    assert failed_ids == set(M['baseline_failure_ids']), failed_ids
    guard(source)
    c = pytest('candidate-new-tests', repair_args, source)
    assert c['passed'] == 19 and c['failed'] == c['errors'] == c['skipped'] == 0
    collected = {}
    collection_times = []
    # Only family unions need D0 collection; all jobs collect their own selection.
    family_names = [name for names in M['families'].values() for name in names]
    for name in family_names:
        r = next(row for row in ROWS if row['name'] == name)
        t = time.monotonic()
        collected[name] = collection(name, r['args'], r['env'], source)
        collection_times.append(time.monotonic() - t)
    t = time.monotonic()
    full = collection('model-original', ['-k', 'not test_example', '--ignore=test/infer/',
        '--ignore=test/contrib/'], {'CI': '1'}, source)
    collection_times.append(time.monotonic() - t)
    t = time.monotonic()
    infer_full = collection('inference-original',
        ['test/infer', '--ignore=test/infer/test_mcmc.py', '--ignore=test/contrib/test_nested_sampling.py'],
        {'CI': 'true'}, source)
    collection_times.append(time.monotonic() - t)
    for label, original in [('model', full), ('inference', infer_full)]:
        family = [collected[name] for name in M['families'][label]]
        assert sum(map(len, family)) == len(set.union(*family))
        assert set.union(*family) == original
    stop = threading.Event()
    samples = []
    errors = []
    def sample_anon():
        try:
            while not stop.is_set():
                stat = dict(line.split() for line in Path('/sys/fs/cgroup/memory.stat').read_text().splitlines())
                samples.append({'at': time.time(), 'bytes': int(stat['anon']) + int(stat.get('shmem', 0))})
                stop.wait(1)
        except BaseException as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=sample_anon, daemon=True)
    thread.start()
    try:
        pytest('calibration-pair', [a['node'] for a in M['calibration']], source,
               env={'CI': '1'}, workers=2)
    finally:
        stop.set()
        thread.join(timeout=3)
        save('calibration-memory', {'samples': samples, 'errors': errors})
    assert samples and not errors
    durations = {}
    for case in ET.parse(E / 'calibration-pair.xml').iter('testcase'):
        ids = {x.attrib['value'] for x in case.findall('./properties/property')
               if x.attrib['name'] == 'exact_nodeid'}
        assert len(ids) == 1
        durations[ids.pop()] = float(case.attrib['time'])
    ratios = [durations[a['node']] / a['reference_seconds'] for a in M['calibration']]
    peak = int(Path('/sys/fs/cgroup/memory.peak').read_text())
    anon_peak = max(s['bytes'] for s in samples)
    setup = json.loads((E / 'setup-price.json').read_text())['whole_job_overhead_seconds']
    collect_max = max(collection_times)
    ratio = max(1, *ratios)
    projections = {r['name']: r['reference_seconds'] * ratio /
                   (M['parallel_speedup'] if r['workers'] else 1) + max(300, setup) * 1.25
                   for r in ROWS}
    remaining = DEADLINE - time.time()
    # Actual matrix runs quality concurrently with all science groups.
    bundles = json.loads((P / 'bundles.json').read_text())
    group_times = {b['label']: sum(projections[n] - max(300, setup) * 1.25 for n in b['commands'])
                   + max(300, setup) * 1.25 + len(b['commands']) * collect_max
                   for b in bundles if b['commands']}
    quality_time = max(M['quality_reserve_seconds'], 171 * ratio + 600) + max(300, setup) * 1.25
    required = max(max(group_times.values()), quality_time) + M['artifact_reserve_seconds']
    gate = {'ratio': ratio, 'informational_cgroup_peak_bytes': peak,
            'calibration_anon_shmem_peak_bytes': anon_peak, 'overhead_seconds': setup,
            'maximum_collection_seconds': collect_max, 'projections': projections,
            'bundle_projection': group_times, 'quality_projection': quality_time,
            'remaining_seconds': remaining, 'required_seconds': required,
            'admitted': required <= remaining and anon_peak <= M['calibration_peak_max_gib'] * 2**30}
    save('full-gate', gate)
    assert gate['admitted'], 'FULL_STAGE_PARKED_NO_SCOPE_REDUCTION'


def scientific(source, name):
    r = next(x for x in ROWS if x['name'] == name)
    selected = collection(name, r['args'], r['env'], source)
    guard(source)
    try:
        pytest(name, r['args'], source, env=r['env'], workers=r['workers'])
        executed = {x.attrib['value'] for x in ET.parse(E / (name + '.xml')).iter('property')
                    if x.attrib['name'] == 'exact_nodeid'}
        assert selected == executed, 'COLLECTION_EXECUTION_ID_MISMATCH'
    except RuntimeError:
        if r['workers']:
            diagnose(name, source, env=r['env'])
        raise


def quality(source):
    env = dict(BASE_ENV, PATH='/work/venv/bin:/work/tool/bin:' + BASE_ENV['PATH'])

    def hooks():
        run('hook-pins', [PY, '-c',
            'import yaml,json;from pathlib import Path;d=yaml.safe_load(Path(".pre-commit-config.yaml").read_text());'
            'r={x["repo"]:x["rev"] for x in d["repos"] if x["repo"]!="local"};'
            'print(json.dumps(r));assert r==json.loads(Path("/inputs/manifest.json").read_text())["hook_revisions"]'],
            cwd=source, env=env)
        hook_repos = []
        resolution_errors = []
        try:
            run('hooks', ['prek', 'run', '--all-files', '--skip', 'ruff', '--skip', 'ruff-format'],
                cwd=source, env=env, seconds=900)
        finally:
            cache = W / 'prek-cache/repos'
            cancelling = isinstance(sys.exc_info()[1], (SystemExit, KeyboardInterrupt))
            save('hook-cache-directory-listing', [str(path.relative_to(cache))
                 for path in sorted(cache.glob('*'))] if cache.exists() else [])
            if cancelling:
                resolution_errors.append({'state': 'CANCELLED_NO_MORE_GIT_COMMANDS'})
            for index, repo in enumerate([] if cancelling else sorted(cache.glob('*'))):
                if not repo.is_dir():
                    continue
                try:
                    marker = json.loads((repo / '.prek-repo.json').read_text())
                    head = run('hook-resolved-' + str(index), ['git', '-C', str(repo), 'rev-parse', 'HEAD']).strip()
                    remote = run('hook-origin-' + str(index), ['git', '-C', str(repo), 'remote', 'get-url', 'origin']).strip()
                    assert marker['repo'] in M['hook_revisions']
                    assert marker['rev'] == M['hook_revisions'][marker['repo']]
                    hook_repos.append({'cache_path': str(repo), 'head': head, 'origin': remote, 'marker': marker})
                except Exception as exc:
                    resolution_errors.append({'path': str(repo), 'error': repr(exc)})
            save('hook-resolved-revisions', {'repos': hook_repos, 'errors': resolution_errors})
        if resolution_errors or not hook_repos or not set(M['hook_revisions']) <= {r['origin'].removesuffix('.git') for r in hook_repos}:
            raise RuntimeError('HOOK_RESOLUTION_UNVERIFIED')
        source_invariant(source, 'after-hooks')

    groups = [
        ('lint', lambda: run('lint', ['make', 'lint'], cwd=source, env=env)),
        ('hooks', hooks),
        ('docs', lambda: run('docs', ['make', 'docs'], cwd=source, env=env, seconds=600)),
        ('doctest', lambda: run('doctest', ['make', 'doctest'], cwd=source, env=env, seconds=600)),
        ('readme', lambda: run('readme-doctest', [PY, '-m', 'doctest', '-v', 'README.md'], cwd=source, env=env)),
        ('shipping', lambda: shipping(source, env)),
    ]
    failures = []
    for label, action in groups:
        try:
            action()
        except Exception as exc:
            failures.append({'group': label, 'error': repr(exc)})
    save('quality-groups-failures', failures)
    if failures:
        raise RuntimeError('QUALITY_GROUPS_FAILED: ' + repr(failures))


def shipping(source, env):
    run('build', UV + ['build', '--python', PY, '--no-build-isolation', '--out-dir', '/work/dist'],
        cwd=source, env=env)
    wheels = list((W / 'dist').glob('*.whl'))
    assert len(wheels) == 1 and len(list((W / 'dist').glob('*.tar.gz'))) == 1
    ip = '/work/installed-env/bin/python'
    run('installed-venv', UV + ['venv', '/work/installed-env', '--python', sys.executable])
    run('installed-sync', UV + ['-v', 'pip', 'sync', '--python', ip, '--build-constraints',
        '/inputs/build-constraints.txt', '/inputs/closure.txt'], seconds=600)
    run('installed-wheel', UV + ['pip', 'install', '--python', ip, '--no-deps', str(wheels[0])])
    guard(source, python=ip, installed=True)
    import shutil
    wheel_check = W / 'wheel-check'
    wheel_check.mkdir()
    shutil.copytree(source / 'test', wheel_check / 'test')
    shutil.copyfile(source / 'pyproject.toml', wheel_check / 'pyproject.toml')
    r = pytest('installed-new-tests', ['test/infer/test_infer_util.py',
        'test/infer/test_autoguide.py', '-k', ' or '.join(M['repair_names'])], wheel_check, python=ip)
    assert r['passed'] == 19 and r['failed'] == r['errors'] == r['skipped'] == 0
    pytest('installed-mcmc-smoke', ['test/infer/test_mcmc.py::test_chain_inside_jit'],
           wheel_check, python=ip)


mode = sys.argv[1]
try:
    source = prepare()
    if mode == 'd0':
        d0(source)
    elif mode == 'quality':
        quality(source)
    else:
        failures = []
        for name in mode.split(','):
            try:
                scientific(source, name)
            except Exception as exc:
                failures.append({'command': name, 'error': repr(exc)})
        if failures:
            save('bundle-failures', failures)
            raise RuntimeError('BUNDLE_FAILURES: ' + repr(failures))
    source_invariant(source, 'final-source')
    save('terminal', {'state': 'PASS', 'mode': mode})
except BaseException as exc:
    save('terminal', {'state': 'FAIL', 'mode': mode, 'error': repr(exc)})
    raise
