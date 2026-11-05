"""CAR packet DRAFT: requires exact patch/controller approval before dispatch."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
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
                PREK_HOME='/work/prek-cache', PYTEST_ADDOPTS='', PYTHONPATH='', CI='true',
                GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
UV = [sys.executable, '-m', 'uv']
PY = '/work/venv/bin/python'
GUARD_COUNT = 0
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
    root = Path('/sys/fs/cgroup')
    peak = root / 'memory.peak'
    assert peak.is_file(), 'CGROUP_V2_PEAK_REQUIRED'
    result = {'at': time.time(), 'memory_peak_bytes': int(peak.read_text()),
              'memory_current_bytes': int((root / 'memory.current').read_text()),
              'memory_max': (root / 'memory.max').read_text().strip(),
              'memory_events': dict(line.split() for line in (root / 'memory.events').read_text().splitlines()),
              'memory_stat': dict(line.split() for line in (root / 'memory.stat').read_text().splitlines()),
              'memory_swap_peak_bytes': int((root / 'memory.swap.peak').read_text()) if (root / 'memory.swap.peak').is_file() else None,
              'cpu_stat': dict(line.split() for line in (root / 'cpu.stat').read_text().splitlines())}
    save(label, result)
    return result


def guard(source, python=PY, baseline=False, installed=False, module='numpyro',
          file_rel='distributions/continuous.py', expected_sha=None):
    global GUARD_COUNT
    GUARD_COUNT += 1
    expected = expected_sha or M['baseline_sha256' if baseline else 'candidate_sha256']['numpyro/distributions/continuous.py']
    code = "import hashlib,importlib,importlib.metadata,json,pathlib\nm=importlib.import_module(MODULE)\np=pathlib.Path(m.__file__).resolve()\nassert hashlib.sha256((p.parent / FILE_REL).read_bytes()).hexdigest()==EXPECTED\nmetadata=importlib.metadata.distribution(MODULE)\nraw=metadata.read_text('direct_url.json')\nprint(json.dumps({'file':str(p),'direct_url':raw,'version':metadata.version}))\nassert len([d for d in importlib.metadata.distributions() if d.metadata['Name'].lower().replace('-','_')==MODULE])==1\nif INSTALLED:\n assert 'site-packages' in str(p) and not str(p).startswith(SOURCE+'/')\nelse:\n assert str(p).startswith(SOURCE+'/')\n direct=json.loads(raw)\n assert direct['dir_info']['editable'] is True\n assert direct['url']=='file://'+SOURCE\n"
    code = chr(10).join([
        'EXPECTED='+repr(expected), 'SOURCE='+repr(str(source)),
        'INSTALLED='+repr(installed), 'MODULE='+repr(module),
        'FILE_REL='+repr(file_rel), code])
    run('guard-'+source.name+('-wheel' if installed else '')+'-'+str(GUARD_COUNT), [python,'-c',code], cwd=source if not installed else W)


def source_invariant(source, label, baseline=False, probe=False):
    assert run(label+'-head',['git','rev-parse','HEAD'],cwd=source).strip()==M['base']
    expected=M['baseline_blobs' if baseline else 'candidate_blobs']
    for path,oid in expected.items():
        assert run(label+'-'+Path(path).stem,['git','hash-object',path],cwd=source).strip()==oid
    status=run(label+'-status',['git','status','--porcelain','--untracked-files=no'],cwd=source)
    actual={line[3:] for line in status.splitlines()}
    allowed=set() if baseline else set(M['baseline_blobs'])
    assert actual==allowed,(actual,allowed)
    untracked=run(label+'-untracked',['git','ls-files','--others','--exclude-standard'],cwd=source).splitlines()
    assert not any(path.startswith('numpyro/') and path.endswith('.py') for path in untracked),untracked
    save(label+'-untracked-record',{'paths':untracked,'note':'Test-generated data is retained; every authored source/test byte is separately hash-verified.'})
    run(label+'-diff',['git','diff','--full-index'],cwd=source)


def classify_failures(xml, expected):
    cases=list(ET.parse(xml).iter('testcase'))
    assert cases and len(cases)==len(expected)
    observed={}
    for case in cases:
        ids={x.attrib['value'] for x in case.findall('./properties/property') if x.attrib['name']=='exact_nodeid'}
        assert len(ids)==1
        node=ids.pop()
        assert node in expected and node not in observed
        failure=case.find('failure')
        assert failure is not None and case.find('error') is None and case.find('skipped') is None
        message=failure.get('message','').strip()
        actual_type=message.split(':',1)[0].strip()
        assert actual_type==expected[node],(node,expected[node],message[:300])
        observed[node]=expected[node]
    assert set(observed)==set(expected)
    return observed


def new_fixtures():
    # Real isolated editable installs exercise source/hash/direct_url guards.
    run('tiny-restored-test-tools',UV+['pip','install','--python','/work/fixture-env/bin/python',
        '--no-deps','--require-hashes','-r','/inputs/fixture-tools.txt'])
    run('tiny-backend-tools',UV+['pip','install','--python','/work/fixture-env/bin/python',
        '--no-deps','--require-hashes','-r','/inputs/tiny-build-tools.txt'])
    for side,value in [('baseline',-1),('candidate',1)]:
        root=W/('identity-'+side)
        (root/'identity_fixture').mkdir(parents=True)
        (root/'identity_fixture/__init__.py').write_text('')
        raw=('VALUE = '+str(value)+'\n').encode()
        (root/'identity_fixture/state.py').write_bytes(raw)
        (root/'pyproject.toml').write_text('[build-system]\nrequires=["setuptools>=77","wheel"]\nbuild-backend="setuptools.build_meta"\n[project]\nname="identity-fixture"\nversion="0.0.1"\n')
        run('tiny-editable-'+side,UV+['pip','install','--python','/work/fixture-env/bin/python',
            '--no-deps','--no-build-isolation','--editable',str(root)])
        guard(root,python='/work/fixture-env/bin/python',module='identity_fixture',file_rel='state.py',
              expected_sha=hashlib.sha256(raw).hexdigest())
        try:
            guard(root,python='/work/fixture-env/bin/python',module='identity_fixture',file_rel='state.py',expected_sha='0'*64)
        except RuntimeError:
            pass
        else:
            raise AssertionError('wrong source hash was accepted')
    fixture=W/'classifier-fixture'
    fixture.mkdir()
    (fixture/'test_classifier.py').write_text('class Car:\n @property\n def variance(self):\n  raise NotImplementedError\n\ndef test_covariance():\n Car().covariance_matrix\n\ndef test_variance():\n Car().variance\n')
    pytest('classifier-valid',['test_classifier.py'],fixture,python='/work/fixture-env/bin/python',expected=(1,))
    expected={'test_classifier.py::test_covariance':'AttributeError',
              'test_classifier.py::test_variance':'NotImplementedError'}
    classify_failures(E/'classifier-valid.xml',expected)
    wrong=dict(expected);wrong['test_classifier.py::test_variance']='TypeError'
    try:
        classify_failures(E/'classifier-valid.xml',wrong)
    except AssertionError:
        save('classifier-negative',{'wrong_exception_rejected':True})
    else:
        raise AssertionError('wrong exception accepted')
    false_positive=ET.parse(E/'classifier-valid.xml')
    for case in false_positive.iter('testcase'):
        if case.get('name')=='test_variance':
            case.find('failure').set('message','AssertionError: mentions NotImplementedError')
    false_positive.write(E/'classifier-false-positive.xml')
    try:
        classify_failures(E/'classifier-false-positive.xml',expected)
    except AssertionError:
        save('classifier-false-positive-rejected',{'message_reference_is_not_exception_type':True})
    else:
        raise AssertionError('exception name mentioned inside assertion was accepted')
    resources('fixture-cgroup-peak')


def prepare_source():
    new_fixtures()
    source=W/'candidate'
    run('source-init',['git','init','--quiet',str(source)])
    run('source-fetch',['git','-c','core.hooksPath=/dev/null','fetch','--depth=1',M['source_url'],M['base']],seconds=90)
    run('source-checkout',['git','-c','core.hooksPath=/dev/null','checkout','--detach','--quiet','FETCH_HEAD'],cwd=source)
    run('source-apply-check',['git','apply','--check','/inputs/feature.patch'],cwd=source)
    run('source-apply',['git','apply','/inputs/feature.patch'],cwd=source)
    source_invariant(source,'after-apply')
    run('venv',UV+['venv','/work/venv','--python',sys.executable])
    t=time.monotonic()
    run('sync',UV+['-v','pip','sync','--python',PY,'--build-constraints','/inputs/build-constraints.txt','/inputs/closure.txt'],seconds=600)
    run('freeze-before-overlay',UV+['pip','freeze','--python',PY])
    run('overlay',UV+['pip','install','--python',PY,'--no-deps','--require-hashes','-r','/inputs/overlay.txt'])
    run('source-editable',UV+['pip','install','--python',PY,'--no-deps','--no-build-isolation','--editable',str(source)])
    run('pip-check',UV+['pip','check','--python',PY])
    run('freeze-after-overlay',UV+['pip','freeze','--python',PY])
    save('setup-price',{'install_seconds':time.monotonic()-t,
        'whole_job_overhead_seconds':time.time()-float(os.environ['CAR_JOB_STARTED']),
        'elapsed_since_workflow_origin':time.time()-ORIGIN})
    guard(source)
    return source


def d0(source):
    # Catch formatting/typing before any expensive scientific matrix.
    env=dict(BASE_ENV,PATH='/work/venv/bin:/work/tool/bin:'+BASE_ENV['PATH'])
    run('early-full-lint',['make','lint'],cwd=source,env=env)
    baseline=W/'baseline'
    run('baseline-clone',['git','clone','--local','--no-hardlinks',str(source),str(baseline)])
    # clone copies committed master, NOT the working-tree feature overlay.
    (baseline/'test/test_car_moments.py').write_bytes((source/'test/test_car_moments.py').read_bytes())
    assert hashlib.sha256((baseline/'test/test_car_moments.py').read_bytes()).hexdigest()==M['candidate_sha256']['test/test_car_moments.py']
    source_invariant(baseline,'baseline-probe',baseline=True,probe=True)
    bp='/work/baseline-env/bin/python'
    run('baseline-venv',UV+['venv','/work/baseline-env','--python',sys.executable])
    run('baseline-sync',UV+['pip','sync','--python',bp,'--build-constraints','/inputs/build-constraints.txt','/inputs/closure.txt'])
    run('baseline-overlay',UV+['pip','install','--python',bp,'--no-deps','--require-hashes','-r','/inputs/overlay.txt'])
    run('baseline-editable',UV+['pip','install','--python',bp,'--no-deps','--no-build-isolation','--editable',str(baseline)])
    guard(baseline,python=bp,baseline=True)
    ids=collection('new-car-tests',['test/test_car_moments.py'],{},source)
    assert len(ids)==20
    expected={node:M['baseline_exception_by_function'][node.split('::')[1].split('[')[0]] for node in ids}
    r=pytest('baseline-new-tests',['test/test_car_moments.py'],baseline,python=bp,expected=(1,))
    assert r=={'total':20,'failed':20,'errors':0,'skipped':0,'passed':0}
    save('baseline-exceptions',classify_failures(E/'baseline-new-tests.xml',expected))
    r=pytest('candidate-new-tests',['test/test_car_moments.py'],source)
    assert r=={'total':20,'failed':0,'errors':0,'skipped':0,'passed':20}
    for label,root,python in [('baseline-car-controls',baseline,bp),('candidate-car-controls',source,PY)]:
        args=['test/test_distributions.py','-k','CAR']
        selected=collection(label,args,{},root,python=python)
        result=pytest(label,args,root,python=python)
        assert result['failed']==result['errors']==0 and result['passed']>0
        executed={x.attrib['value'] for x in ET.parse(E/(label+'.xml')).iter('property') if x.attrib['name']=='exact_nodeid'}
        assert executed==selected
        save(label+'-disclosure',{'counts':result,'includes_existing_skips':True,
            'generic_vacuous_pass_or_skip_is_not_fail_before_proof':True})
    r=pytest('candidate-car-mean-var',['test/test_distributions.py::test_mean_var','-k','CAR'],source)
    assert r=={'total':3,'failed':0,'errors':0,'skipped':0,'passed':3}
    r=pytest('candidate-car-output',['test/test_distributions.py::test_output_is_array','-k','CAR and variance'],source)
    assert r=={'total':6,'failed':0,'errors':0,'skipped':0,'passed':6}
    # Resolve the calibration node from current collection; no stale param index.
    calibration=collection('calibration-model',['test/test_distributions.py::test_mean_var','-k','GaussianCopulaBeta'],{'CI':'1'},source)
    assert len(calibration)==1
    result=pytest('calibration-model',sorted(calibration),source,env={'CI':'1'})
    assert result['passed']==1 and result['skipped']==result['failed']==result['errors']==0
    case=next(ET.parse(E/'calibration-model.xml').iter('testcase'))
    ratio=max(1,float(case.attrib['time'])/M['observed_calibration_seconds'])
    collected={}
    for name in [n for group in M['families'].values() for n in group]:
        row=next(x for x in ROWS if x['name']==name)
        collected[name]=collection(name,row['args'],row['env'],source)
    full_model=collection('model-original',['-k','not test_example','--ignore=test/infer/','--ignore=test/contrib/'],{'CI':'1'},source)
    full_infer=collection('inference-original',['test/infer','--ignore=test/infer/test_mcmc.py','--ignore=test/contrib/test_nested_sampling.py'],{'CI':'true'},source)
    for family,original in [('model',full_model),('inference',full_infer)]:
        sets=[collected[n] for n in M['families'][family]]
        assert sum(map(len,sets))==len(set.union(*sets)) and set.union(*sets)==original
    assert ids <= full_model
    # These supplementary modes really include the new file, unlike upstream's
    # x64 powerLaw/Dagum-only command. The original variant remains unchanged.
    result=pytest('car-x64',['test/test_car_moments.py'],source,env={'JAX_ENABLE_X64':'1'})
    assert result['passed']==20 and result['skipped']==result['failed']==result['errors']==0
    result=pytest('car-tracer',['test/test_car_moments.py::test_car_jitted_moments_do_not_cache_tracers'],source,env={'JAX_CHECK_TRACER_LEAKS':'1'})
    assert result['passed']==2 and result['skipped']==result['failed']==result['errors']==0
    projection={k:v*max(1.25,ratio)+M['car_extra_seconds'] for k,v in M['observed_bundle_job_seconds'].items()}
    projection['quality']=M['quality_projection_seconds']
    required=max(projection.values())+M['queue_reserve_seconds']+M['artifact_reserve_seconds']
    observed=resources('D0-cgroup-final')
    gate={'ratio':ratio,'predicted_bundle_seconds':projection,'required_seconds':required,
        'remaining_seconds':DEADLINE-time.time(),'elapsed_since_origin':time.time()-ORIGIN,
        'candidate_matrix':'all23commands+quality,baselineaffectedproofonly_pending_review_scope_revision',
        'full_suite_memory_peak':'UNKNOWNuntilactualCARfulljobs','calibration_peak_bytes':observed['memory_peak_bytes'],
        'admitted':required<=DEADLINE-time.time() and int(observed['memory_events']['oom_kill'])==0}
    save('full-gate',gate)
    assert gate['admitted'],'FULL_STAGE_NOT_ADMITTED_NO_SCOPE_REDUCTION'


def shipping(source,env):
    run('build',UV+['build','--python',PY,'--no-build-isolation','--out-dir','/work/dist'],cwd=source,env=env)
    wheels=list((W/'dist').glob('*.whl'))
    assert len(wheels)==len(list((W/'dist').glob('*.tar.gz')))==1
    ip='/work/installed-env/bin/python'
    run('installed-venv',UV+['venv','/work/installed-env','--python',sys.executable])
    run('installed-sync',UV+['pip','sync','--python',ip,'--build-constraints','/inputs/build-constraints.txt','/inputs/closure.txt'])
    run('installed-wheel',UV+['pip','install','--python',ip,'--no-deps',str(wheels[0])])
    run('installed-pip-check',UV+['pip','check','--python',ip])
    guard(source,python=ip,installed=True)
    check=W/'wheel-check'
    check.mkdir()
    shutil.copytree(source/'test',check/'test')
    shutil.copyfile(source/'pyproject.toml',check/'pyproject.toml')
    result=pytest('installed-car-tests',['test/test_car_moments.py'],check,python=ip)
    assert result=={'total':20,'failed':0,'errors':0,'skipped':0,'passed':20}
    # Real public inference consumer; explicitly unset CI to avoid existing skips.
    smoke_env={'CI':'','XLA_FLAGS':'--xla_force_host_platform_device_count=2'}
    smoke=pytest('installed-mcmc-smoke',['test/infer/test_mcmc.py::test_chain_inside_jit'],check,python=ip,env=smoke_env)
    assert smoke['passed']>0 and smoke['failed']==smoke['errors']==0
    assert smoke['skipped']==0


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
    return prepare_source()


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

    def format_guard():
        run('format', ['make', 'format'], cwd=source, env=env)
        source_invariant(source, 'after-format')

    groups = [
        ('lint', lambda: run('lint', ['make', 'lint'], cwd=source, env=env)),
        ('format', format_guard),
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
mode=sys.argv[1]
try:
    resources('cgroup-start')
    source=prepare()
    if mode=='d0':
        d0(source)
    elif mode=='quality':
        quality(source)
    else:
        failures=[]
        for name in mode.split(','):
            try:
                scientific(source,name)
            except Exception as exc:
                failures.append({'command':name,'error':repr(exc)})
        if failures:
            save('bundle-failures',failures)
            raise RuntimeError('BUNDLE_FAILURES')
    source_invariant(source,'final-source')
    save('terminal',{'state':'PASS','mode':mode})
except BaseException as exc:
    save('terminal',{'state':'FAIL','mode':mode,'error':repr(exc)})
    raise
finally:
    resources('cgroup-final')
