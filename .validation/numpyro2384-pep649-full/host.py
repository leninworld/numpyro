"""Own one isolated hosted Docker job; no Mac Docker/storage operations."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

P = Path(__file__).resolve().parent
M = json.loads((P / 'manifest.json').read_text())
origin = int(os.environ['PACKET_ORIGIN'])
deadline = origin + M['deadline_seconds']
W = Path(os.environ['RUNNER_TEMP']) / ('numpyro2384-pep649-full-' + os.environ['JOB_LABEL'])
E = W / 'evidence'
E.mkdir(parents=True, exist_ok=False)
name = 'numpyro2384-pep649-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['JOB_LABEL']
started = time.time()
sequence = 0


def run(label, argv, limit=300):
    global sequence
    sequence += 1
    label = str(sequence).zfill(4) + '-' + label
    allowance = min(limit, deadline - time.time())
    if allowance <= 0:
        raise RuntimeError('WHOLE_PACKET_DEADLINE')
    status = {'argv': argv, 'timeout': allowance}
    try:
        with (E / (label + '.stdout')).open('wb') as out, (E / (label + '.stderr')).open('wb') as err:
            p = subprocess.run(argv, stdout=out, stderr=err, timeout=allowance)
            status['returncode'] = p.returncode
        assert p.returncode == 0, label
    except subprocess.TimeoutExpired:
        status['state'] = 'TIMEOUT'
        raise
    finally:
        (E / (label + '.json')).write_text(json.dumps(status, indent=2))
    return (E / (label + '.stdout')).read_text()


try:
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.environ['GITHUB_REPOSITORY'] == 'leninworld/numpyro'
    assert os.environ['GITHUB_RUN_ATTEMPT'] == '1', 'No automatic rerun authority'
    assert os.environ['GITHUB_RUN_NUMBER'] == '1', 'This new workflow permits one initial activation only'
    assert M['execution_enabled'] is True, 'EXACT_EXECUTION_APPROVAL_REQUIRED'
    mem = {x.split(':')[0]: int(x.split()[1]) * 1024 for x in Path('/proc/meminfo').read_text().splitlines()}
    free = os.statvfs(W).f_bavail * os.statvfs(W).f_frsize
    (E / 'admission.json').write_text(json.dumps({'memory': mem, 'free_bytes': free}, indent=2))
    assert mem['MemAvailable'] >= M['host_min_available_gib'] * 2**30
    assert mem['MemTotal'] >= M['host_min_total_gib'] * 2**30
    assert free >= M['host_min_disk_gib'] * 2**30
    label=os.environ['JOB_LABEL']
    if label=='d0':
        minimum=M['D0_minimum_total_remaining_seconds']
    else:
        prices=json.loads(os.environ['VALIDATION_PRICE_JSON'])
        assert label in prices and 0<float(prices[label])<3600
        minimum=float(prices[label])+M['artifact_reserve_seconds']
    assert deadline-time.time() >= minimum, 'INSUFFICIENT_COMMON_BUDGET'
    lane='12' if label.startswith('lower-') else '14'
    run('image-build', ['docker', 'build', '--tag', name, '--file', str(P / ('Dockerfile'+lane)), str(P)], 300)
    run('container-create', ['docker', 'create', '--name', name, '--init',
        '--user', str(os.getuid()) + ':' + str(os.getgid()),
        '--env', 'USER=validator', '--env', 'LOGNAME=validator', '--memory', '13g',
        '--memory-swap', '13g', '--cpus', '3', '--security-opt', 'no-new-privileges',
        '--cap-drop', 'ALL', '--mount', 'type=bind,src=' + str(P) + ',dst=/inputs,readonly',
        '--mount', 'type=bind,src=' + str(W) + ',dst=/work', '--env', 'PACKET_ORIGIN=' + str(origin),
        '--env', 'JOB_STARTED=' + str(started), '--env', 'PYTHON_LANE=' + lane,
        name, 'python', '/inputs/inside.py', sys.argv[1]])
    run('container-start', ['docker', 'start', name], 30)
    while True:
        state = json.loads(run('inspect-current', ['docker', 'inspect', name], 15))[0]['State']
        if not state['Running']:
            assert state['ExitCode'] == 0 and not state['OOMKilled'], state
            break
        floor = os.statvfs(W).f_bavail * os.statvfs(W).f_frsize
        if floor < M['disk_free_floor_gib'] * 2**30 or time.time() >= deadline - 90:
            raise RuntimeError('DISK_FLOOR_OR_COMMON_DEADLINE')
        run('stats-' + str(int(time.time())), ['docker', 'stats', '--no-stream', '--format', '{{json .}}', name], 15)
        time.sleep(10)
    run('logs', ['docker', 'logs', name], 30)
    (E / 'host-terminal.json').write_text(json.dumps({'state': 'PASS', 'origin': origin, 'elapsed': time.time() - started}))
finally:
    # Stop only the container created by this exact owned job. Never remove/prune.
    with (E / 'owned-stop.stdout').open('wb') as out, (E / 'owned-stop.stderr').open('wb') as err:
        result = subprocess.run(['docker', 'stop', '--time', '10', name], stdout=out, stderr=err, timeout=20)
    (E / 'owned-stop.json').write_text(json.dumps({'returncode': result.returncode}))
    for label, argv in [('terminal-inspect', ['docker', 'inspect', name]),
                        ('terminal-logs', ['docker', 'logs', name])]:
        with (E / (label + '.stdout')).open('wb') as out, (E / (label + '.stderr')).open('wb') as err:
            p = subprocess.run(argv, stdout=out, stderr=err, timeout=20)
        (E / (label + '.json')).write_text(json.dumps({'returncode': p.returncode}))
