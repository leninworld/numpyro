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

from evidence_reader import junit_counts

P = Path('/inputs')
W = Path('/work')
E = W / 'evidence'
E.mkdir(parents=True, exist_ok=True)
M = json.loads((P / 'manifest.json').read_text())
M.update(M['lanes'][os.environ['PYTHON_LANE']])
ROWS = json.loads((P / 'commands.json').read_text())
ORIGIN = int(os.environ['PACKET_ORIGIN'])
DEADLINE = ORIGIN + M['deadline_seconds'] - 150
BASE_ENV = dict(os.environ, HOME='/work/home', UV_CACHE_DIR='/work/uv-cache',
                PREK_HOME='/work/prek-cache', PYTEST_ADDOPTS='', PYTHONPATH='', CI='true')
UV = [sys.executable, '-m', 'uv']
PY = '/work/venv/bin/python'
CLOSURE = '/inputs/closure'+str(sys.version_info.minor)+'.txt'
BASE_ENV.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')






def terminated(signum, frame):
    raise SystemExit(143)

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
    assert {line[3:] for line in status.splitlines()} == set(M['changed_paths']), status
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
    result = junit_counts(xml)
    save(name + '-counts', result)
    return result

def collection(name, args, env, source, python=PY):
    # Same real pytest collection and environment as the execution command.
    output = E / (name + '-ids.json')
    plugin = W / 'collection_recorder.py'
    plugin.write_text('import json,os\nfrom pathlib import Path\n'
                      'def pytest_collection_finish(session):\n'
                      ' Path(os.environ["COLLECT_IDS"]).write_text(json.dumps([i.nodeid for i in session.items]))\n')
    e = dict(BASE_ENV, **env)
    e.update(PYTHONPATH=str(W), COLLECT_IDS=str(output))
    run('collect-' + name, [python, '-m', 'pytest', '--collect-only', '-q', '-p',
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

def resources(label):
    root=Path('/sys/fs/cgroup')
    result={'at':time.time(),'memory_peak_bytes':int((root/'memory.peak').read_text()),
      'memory_current_bytes':int((root/'memory.current').read_text()),
      'memory_max':(root/'memory.max').read_text().strip(),
      'memory_events':dict(line.split() for line in (root/'memory.events').read_text().splitlines()),
      'memory_stat':dict(line.split() for line in (root/'memory.stat').read_text().splitlines()),
      'swap_peak':int((root/'memory.swap.peak').read_text()) if (root/'memory.swap.peak').exists() else None}
    save(label,result);return result

def source_tree(label, source, url, ref):
    run(label+'-init',['git','init','--quiet',str(source)])
    run(label+'-fetch',['git','-C',str(source),'fetch','--depth=1',url,ref],seconds=90)
    run(label+'-checkout',['git','-C',str(source),'checkout','--detach','--quiet','FETCH_HEAD'])
    assert run(label+'-head',['git','-C',str(source),'rev-parse','HEAD']).strip()==ref
    return source

def source_fixture():
    global M
    repo=W/'fixture-source-origin';repo.mkdir()
    contents={'numpyro/infer/util.py':'VALUE = 1\n',
       'test/infer/test_infer_util.py':'def test_one():\n    assert True\n',
       'test/infer/test_autoguide.py':'def test_two():\n    assert True\n','README.md':'fixture\n'}
    for path,text in contents.items():
        file=repo/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(text)
    run('source-fixture-init',['git','init','--quiet',str(repo)])
    run('source-fixture-add',['git','-C',str(repo),'add','.'])
    run('source-fixture-commit',['git','-C',str(repo),'-c','user.name=Fixture',
        '-c','user.email=fixture@example.invalid','commit','--quiet','-m','fixture'])
    ref=run('source-fixture-head',['git','-C',str(repo),'rev-parse','HEAD']).strip()
    # Exercise the exact real checkout helper before any scientific payload.
    target=source_tree('fixture-checkout',W/'fixture-source-clone',repo.as_uri(),ref)
    run('wrong-cwd-negative',['git','fetch','--depth=1',repo.as_uri(),ref],cwd=W,expected=(128,))
    assert 'not a git repository' in (E/'wrong-cwd-negative.stderr').read_text()
    changed='test/infer/test_infer_util.py';(target/changed).write_text('def test_one():\n    assert 1 == 1\n')
    saved=M
    try:
        blobs={path:hashlib.sha1(b'blob '+str(len((target/path).read_bytes())).encode()+b'\0'+(target/path).read_bytes()).hexdigest()
               for path in contents if path!='README.md'}
        M=dict(saved,published=ref,source_blobs=blobs,changed_paths=[changed])
        source_invariant(target,'fixture-positive')
        prod=target/'numpyro/infer/util.py';prod.write_text('VALUE = 2\n')
        try:source_invariant(target,'fixture-wrong-hash')
        except AssertionError:pass
        else:raise AssertionError('WRONG_SOURCE_HASH_NOT_REJECTED')
        prod.write_text(contents['numpyro/infer/util.py'])
        (target/'README.md').write_text('unexpected\n')
        try:source_invariant(target,'fixture-extra-change')
        except AssertionError:pass
        else:raise AssertionError('EXTRA_TRACKED_PATH_NOT_REJECTED')
    finally:M=saved
    save('source-fixture',{'real_checkout':'PASS','wrong_cwd_rejected':True,
        'positive_source_guard':'PASS','wrong_hash_rejected':True,'extra_changed_path_rejected':True})

def focused(source):
    args=['test/infer/test_infer_util.py','test/infer/test_autoguide.py','-k',' or '.join(M['repair_names'])]
    selected=collection('retained-source',args,{},source)
    assert len(selected)==14
    result=pytest('retained-source',args,source)
    assert result=={'total':14,'failed':0,'errors':0,'skipped':0 if sys.version_info>=(3,14) else 2,'passed':14 if sys.version_info>=(3,14) else 12}
    executed={n.attrib['value'] for n in ET.parse(E/'retained-source.xml').iter('property') if n.attrib['name']=='exact_nodeid'}
    assert selected==executed
    save('retained-source-nodeids',sorted(selected))

def calibration_duration(xml_path, expected_nodeid, expected_total):
    cases = list(ET.parse(xml_path).iter('testcase'))
    assert len(cases) == expected_total > 0
    identities = []
    target = []
    for case in cases:
        assert all(case.find(tag) is None for tag in ('failure', 'error', 'skipped'))
        values = [prop.attrib['value'] for prop in case.findall('./properties/property')
                  if prop.attrib.get('name') == 'exact_nodeid']
        assert len(values) == 1
        identities.append(values[0])
        if values[0] == expected_nodeid:
            target.append(case)
    assert len(set(identities)) == len(identities) and len(target) == 1
    seconds = float(target[0].attrib['time'])
    assert 0 <= seconds < 3600
    return seconds


def calibration_reader_fixture():
    actual_path = E / 'fixture-xdist.xml'
    root = ET.parse(actual_path).getroot()
    cases = list(root.iter('testcase'))
    assert len(cases) == 3
    target = cases[-1]
    identity = next(prop.attrib['value'] for prop in target.findall('./properties/property')
                    if prop.attrib.get('name') == 'exact_nodeid')
    assert calibration_duration(actual_path, identity, 3) == float(target.attrib['time'])
    middle_identity = next(prop.attrib['value'] for prop in cases[1].findall('./properties/property')
                           if prop.attrib.get('name') == 'exact_nodeid')
    synthetic = ET.fromstring(ET.tostring(root))
    synthetic_cases = list(synthetic.iter('testcase'))
    for case, seconds in zip(synthetic_cases, ('4.0', '2.25', '1.125')):
        case.set('time', seconds)
    path = E / 'calibration-reader-synthetic.xml'
    ET.ElementTree(synthetic).write(path)
    assert calibration_duration(path, middle_identity, 3) == 2.25
    rejected = []
    for kind in ('duplicate', 'missing-identity', 'missing-target', 'failure', 'bad-time', 'nan-time'):
        changed = ET.fromstring(ET.tostring(synthetic))
        rows = list(changed.iter('testcase'))
        final_properties = rows[-1].find('properties')
        final_identity = next(prop for prop in final_properties
                              if prop.attrib.get('name') == 'exact_nodeid')
        if kind == 'duplicate':
            first = next(prop.attrib['value'] for prop in rows[0].findall('./properties/property')
                         if prop.attrib.get('name') == 'exact_nodeid')
            final_identity.set('value', first)
        elif kind == 'missing-identity':
            final_properties.remove(final_identity)
        elif kind == 'missing-target':
            final_identity.set('value', 'synthetic::different-case')
        elif kind == 'failure':
            ET.SubElement(rows[0], 'failure').text = 'synthetic parser negative control'
        else:
            rows[-1].set('time', 'invalid' if kind == 'bad-time' else 'nan')
        negative_path = E / ('calibration-reader-' + kind + '.xml')
        ET.ElementTree(changed).write(negative_path)
        try:
            calibration_duration(negative_path, identity, 3)
        except (AssertionError, ValueError):
            rejected.append(kind)
        else:
            raise AssertionError('Calibration reader accepted ' + kind)
    assert len(rejected) == 6
    save('calibration-reader-fixture', {'actual_pytest_junit_positive': True,
         'synthetic_middle_identity_seconds': 2.25, 'negative_controls_rejected': rejected})


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
    # Reused real helper fixtures before the frozen scientific environment.
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
    (W / 'fixture/test_fixture.py').write_text('def test_one():\n assert 1 == 1\n\ndef test_two():\n assert 2 == 2\n\ndef test_three():\n assert 3 == 3\n')
    r = pytest('fixture-xdist', [], W / 'fixture', python='/work/fixture-env/bin/python', workers=2)
    assert r == {'total': 3, 'failed': 0, 'errors': 0, 'skipped': 0, 'passed': 3}
    calibration_reader_fixture()
    (W / 'fixture/test_negative.py').write_text('import pytest\n'
        'def test_expected_failure():\n assert False\n'
        '@pytest.fixture\ndef broken():\n raise RuntimeError("intentional setup error")\n'
        'def test_setup_error(broken):\n pass\n')
    r = pytest('fixture-negative', ['test_negative.py'], W / 'fixture',
        python='/work/fixture-env/bin/python', workers=2, expected=(1,))
    assert r['failed'] == 1 and r['errors'] == 1
    run('evidence-reader-real-fixtures', [sys.executable, '/inputs/evidence_reader.py', '--fixtures', str(E/'fixture-xdist.xml'), str(E/'fixture-negative.xml')])
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
    run('backend-fixture-venv', UV + ['venv', '/work/backend-fixture-env', '--python', sys.executable])
    run('build-fixture-sync', UV + ['-v', 'pip', 'sync', '--python', '/work/backend-fixture-env/bin/python',
        '--build-constraints', '/inputs/build-constraints.txt', '/work/fixture-build.txt'], seconds=180)
    build_log = (E / 'build-fixture-sync.stderr').read_text()
    assert '80.9.0' in build_log and '0.45.1' in build_log, 'BUILD_BACKEND_PINS_NOT_OBSERVED'
    save('build-backend-fixture', {'setuptools': '80.9.0', 'wheel': '0.45.1',
        'log': 'build-fixture-sync.stderr', 'hashes': M['backend_metadata_hashes'],
        'note': 'Versions constrained; isolated backend acquisition recorded in verbose uv log. This is not --require-hashes enforcement for VCS builds.'})
    run('fixture-tools-retained', ['/work/fixture-env/bin/python', '-c',
        'import importlib.metadata,pathlib;assert importlib.metadata.version("ruff")=="0.17.1";assert importlib.metadata.version("pytest")=="9.1.1";assert pathlib.Path("/work/fixture-env/bin/ruff").is_file()'])
    run('helper-name-check', ['/work/fixture-env/bin/ruff', 'check', '--select', 'F821,F822,F823'] + [str(x) for x in sorted(P.glob('*.py'))])
    source_fixture()
    source = source_tree('source',W/'candidate',M['source_url'],M['published'])
    run('source-apply-check', ['git', '-C', str(source), 'apply', '--check', '/inputs/repair.patch'])
    run('source-apply', ['git', '-C', str(source), 'apply', '/inputs/repair.patch'])
    source_invariant(source, 'after-apply')
    run('venv', UV + ['venv', '/work/venv', '--python', sys.executable])
    t = time.monotonic()
    # New review5888051951 repair; all prior attempt clocks remain closed.
    run('sync', UV + ['-v', 'pip', 'sync', '--python', PY, '--build-constraints',
        '/inputs/build-constraints.txt', CLOSURE], seconds=600)
    run('freeze-before-overlay', UV + ['pip', 'freeze', '--python', PY])
    run('overlay', UV + ['pip', 'install', '--python', PY, '--no-deps', '--require-hashes',
        '-r', '/inputs/overlay.txt'], seconds=180)
    run('source-editable', UV + ['pip', 'install', '--python', PY, '--no-deps',
        '--no-build-isolation', '--editable', str(source)])
    run('pip-check', UV + ['pip', 'check', '--python', PY])
    run('freeze-after-overlay', UV + ['pip', 'freeze', '--python', PY])
    save('setup-price', {'install_seconds': time.monotonic() - t,
                        'whole_job_overhead_seconds': time.time() - ORIGIN,
                        'cumulative_elapsed_since_original_origin': time.time() - ORIGIN,
                        'measurement_note': 'Attempt-start measures present queue/setup for future-job pricing only. It never changes the original execution deadline.'})
    guard(source)
    return source

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
        '/inputs/build-constraints.txt', CLOSURE], seconds=600)
    run('installed-wheel', UV + ['pip', 'install', '--python', ip, '--no-deps', str(wheels[0])])
    guard(source, python=ip, installed=True)
    import shutil
    wheel_check = W / 'wheel-check'
    wheel_check.mkdir()
    shutil.copytree(source / 'test', wheel_check / 'test')
    shutil.copyfile(source / 'pyproject.toml', wheel_check / 'pyproject.toml')
    wheel_selected=collection('retained-wheel',['test/infer/test_infer_util.py','test/infer/test_autoguide.py','-k',' or '.join(M['repair_names'])],{},wheel_check,python=ip)
    assert wheel_selected==set(json.loads((E/'retained-source-nodeids.json').read_text()))
    r = pytest('installed-new-tests', ['test/infer/test_infer_util.py',
        'test/infer/test_autoguide.py', '-k', ' or '.join(M['repair_names'])], wheel_check, python=ip)
    assert r['passed'] == (14 if sys.version_info >= (3,14) else 12) and r['skipped'] == (0 if sys.version_info >= (3,14) else 2) and r['failed'] == r['errors'] == 0
    wheel_executed={n.attrib['value'] for n in ET.parse(E/'installed-new-tests.xml').iter('property') if n.attrib['name']=='exact_nodeid'}
    assert wheel_executed==wheel_selected
    smoke = pytest('installed-mcmc-smoke', ['test/infer/test_mcmc.py::test_uniform_normal'],
                   wheel_check, python=ip, env={'CI':'','XLA_FLAGS':'--xla_force_host_platform_device_count=2'})
    assert smoke['passed'] == 2 and smoke['skipped'] == smoke['failed'] == smoke['errors'] == 0
def paired(source):
    args=['test/infer/test_infer_util.py','-k','test_init_strategy_value_factory']
    baseline=W/'baseline'
    run('baseline-clone',['git','clone','--local','--no-hardlinks',str(source),str(baseline)])
    # Clone uses unchanged committed head; transfer only the new tests, never candidate util.
    (baseline/'test/infer/test_infer_util.py').write_bytes((source/'test/infer/test_infer_util.py').read_bytes())
    bp='/work/baseline-env/bin/python'
    run('baseline-venv',UV+['venv','/work/baseline-env','--python',sys.executable])
    run('baseline-sync',UV+['pip','sync','--python',bp,'--build-constraints','/inputs/build-constraints.txt',CLOSURE],seconds=600)
    run('baseline-overlay',UV+['pip','install','--python',bp,'--no-deps','--require-hashes','-r','/inputs/overlay.txt'])
    run('baseline-editable',UV+['pip','install','--python',bp,'--no-deps','--no-build-isolation','--editable',str(baseline)])
    guard(baseline,python=bp,baseline=True)
    b=pytest('baseline-value-factory',args,baseline,python=bp,expected=(1,))
    assert b=={'total':2,'failed':2,'errors':0,'skipped':0,'passed':0},b
    for case in ET.parse(E/'baseline-value-factory.xml').iter('testcase'):
        failure=case.find('failure');assert failure is not None
        assert 'AttributeError' in failure.text and 'NoneType' in failure.text
    run('baseline-TYPE_CHECKING',[bp,'/inputs/annotation_contract.py',str(baseline),'candidate'],cwd=W)
    c=pytest('candidate-value-factory',args,source)
    assert c=={'total':2,'failed':0,'errors':0,'skipped':0,'passed':2},c
    run('candidate-TYPE_CHECKING',[PY,'/inputs/annotation_contract.py',str(source),'candidate'],cwd=W)

def d0(source):
    env=dict(BASE_ENV,PATH='/work/venv/bin:/work/tool/bin:'+BASE_ENV['PATH'])
    run('early-lint',['make','lint'],cwd=source,env=env)
    paired(source)
    focused(source)
    collected={}
    for name in [n for group in M['families'].values() for n in group]:
        row=next(x for x in ROWS if x['name']==name)
        collected[name]=collection(name,row['args'],row['env'],source)
    full_model=collection('model-original',['-k','not test_example','--ignore=test/infer/','--ignore=test/contrib/'],{'CI':'1'},source)
    full_infer=collection('inference-original',['test/infer','--ignore=test/infer/test_mcmc.py','--ignore=test/contrib/test_nested_sampling.py'],{'CI':'true'},source)
    coverage={}
    for family,original in [('model',full_model),('inference',full_infer)]:
        sets=[collected[n] for n in M['families'][family]]
        assert sum(map(len,sets))==len(set.union(*sets)) and set.union(*sets)==original
        coverage[family]={'original_count':len(original),'partition_count':sum(map(len,sets)),'union_equal':True,'disjoint':True}
    save('current-selection-unions',coverage)
    r=pytest('calibration',['test/test_distributions.py::test_mean_var','-k','GaussianCopulaBeta'],source,env={'CI':'1'})
    assert r['total']==r['passed']==M['calibration_expected_cases'] and r['failed']==r['errors']==r['skipped']==0
    observed = calibration_duration(E/'calibration.xml', M['observed_calibration_nodeid'], M['calibration_expected_cases'])
    ratio=max(1.5, observed/M['observed_calibration_seconds'])
    projections={k:v*ratio for k,v in M['observed_bundle_job_seconds'].items()}
    projections['quality']=M['quality_projection_seconds']
    for name in M['lower_labels']:projections[name]=M['lower_projection_seconds']
    required=max(projections.values())+M['queue_reserve_seconds']+M['artifact_reserve_seconds']
    snapshot=resources('D0-cgroup-final')
    gate={'ratio':ratio,'predicted_bundle_seconds':projections,'required_seconds':required,'remaining_seconds':DEADLINE-time.time(),
          'admitted':required<=DEADLINE-time.time() and int(snapshot['memory_events']['oom_kill'])==0,'resources':snapshot}
    save('full-gate',gate)
    assert gate['admitted'],'FULL_STAGE_PARKED_NO_SCOPE_REDUCTION'

mode=sys.argv[1]
try:
    assert M['execution_enabled'] is True,'EXACT_EXECUTION_APPROVAL_REQUIRED'
    resources('cgroup-start')
    source=prepare()
    if mode=='d0':d0(source)
    elif mode=='quality':
        focused(source)
        quality(source)
    else:
        failures=[]
        for name in mode.split(','):
            try:scientific(source,name)
            except Exception as exc:failures.append({'command':name,'error':repr(exc)})
        if failures:
            save('bundle-failures',failures)
            raise RuntimeError('BUNDLE_FAILURES: '+repr(failures))
    source_invariant(source,'final-source')
    save('terminal',{'state':'PASS','mode':mode,'python':platform.python_version()})
except BaseException as exc:
    save('terminal',{'state':'FAIL','mode':mode,'error':repr(exc)})
    raise
finally:resources('cgroup-final')
