import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

P = Path(__file__).resolve().parent
ROOT = P.parents[1]
R = Path(os.environ['RUNNER_TEMP']) / 'numpyro2384-closure'
R.mkdir(exist_ok=False)
W = R / 'work'
W.mkdir()
(W / 'evidence').mkdir()
E = W / 'evidence'
started = time.monotonic()
name = 'initialization-dependency-closure'
created = False
process = None
samples = []


def cmd(argv, timeout=20):
    return subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=timeout, text=True)


def amount(s):
    match = re.fullmatch(r'([\d.]+)\s*([A-Za-z]+)', s.strip())
    assert match, s
    units = {'B': 1, 'kB': 1000, 'KB': 1000, 'MB': 1000000, 'GB': 1000000000,
             'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3}
    return float(match[1]) * units[match[2]]


result = {'phase': 'dependency_closure_only', 'project_tests': False, 'project_builds': False}
try:
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('GITHUB_REPOSITORY') == 'leninworld/numpyro'
    assert platform.machine() == 'aarch64'
    assert os.environ.get('GITHUB_WORKFLOW_REF') == 'leninworld/numpyro/.github/workflows/validate-initialization-feedback.yml@refs/heads/validate-initialization-feedback'
    M = json.loads((P / 'manifest.json').read_text())
    for path, expected in M['inputs'].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, path
    memory = {line.split(':')[0]: int(line.split()[1]) * 1024
              for line in Path('/proc/meminfo').read_text().splitlines()}
    assert memory['MemTotal'] >= 12 * 1024**3
    assert memory['MemAvailable'] >= 6 * 1024**3
    assert shutil.disk_usage(R).free >= 10 * 1024**3
    cmd(['docker', 'pull', M['image']], timeout=180)
    selected = json.loads(cmd(['docker', 'image', 'inspect', M['image'], '--format',
        '{"Id":{{json .Id}},"Architecture":{{json .Architecture}},"Os":{{json .Os}},"Size":{{json .Size}}}']))
    assert selected['Architecture'] == 'arm64' and selected['Os'] == 'linux'
    assert selected['Size'] <= 2 * 1024**3
    (E / 'image.json').write_text(json.dumps(selected, indent=2))
    argv = ['docker', 'create', '--name', name, '--user', f'{os.getuid()}:{os.getgid()}',
            '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--memory=2g', '--memory-swap=2g',
            '--cpus=2', '--pids-limit=256', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
            '--mount', f'type=bind,src={P},dst=/inputs,readonly',
            '--mount', f'type=bind,src={W},dst=/work', '--workdir=/work']
    for k, v in {'HOME': '/work/home', 'TMPDIR': '/work/tmp',
                 'UV_CACHE_DIR': '/work/uv-cache', 'UV_PYTHON_DOWNLOADS': 'never',
                 'UV_NO_PROGRESS': '1', 'UV_CONCURRENT_DOWNLOADS': '4',
                 'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                 'GIT_TERMINAL_PROMPT': '0'}.items():
        argv += ['-e', k + '=' + v]
    argv += [M['image'], 'python', '/inputs/inside.py']
    result['container_id'] = cmd(argv).strip()
    created = True
    with (E / 'container.log').open('wb') as log:
        process = subprocess.Popen(['docker', 'start', '-a', name], stdout=log, stderr=subprocess.STDOUT)
        while process.poll() is None:
            assert time.monotonic() - started < 1200, 'ABSOLUTE_TIME_CAP'
            assert int(cmd(['du', '-sb', str(W)]).split()[0]) <= 6 * 1024**3, 'WORKSPACE_CAP'
            assert (E / 'container.log').stat().st_size <= 32 * 1024**2, 'LOG_CAP'
            try:
                stats_text = cmd(['docker', 'stats', '--no-stream', '--format', '{{json .}}', name])
                if not stats_text.strip():
                    state = json.loads(cmd(['docker', 'inspect', name, '--format', '{{json .State}}']))
                    assert not state['Running'], 'EMPTY_STATS_FOR_RUNNING_CONTAINER'
                    result['terminal_stats_race'] = state
                    break
                stats = json.loads(stats_text)
            except subprocess.CalledProcessError:
                state = json.loads(cmd(['docker', 'inspect', name, '--format', '{{json .State}}']))
                if state['Running']:
                    raise
                result['terminal_stats_race'] = state
                break
            traffic = sum(amount(v) for v in stats['NetIO'].split('/'))
            assert traffic <= 2 * 1024**3, 'SAMPLED_CONTAINER_TRAFFIC_CAP'
            samples.append({'elapsed': time.monotonic() - started, 'memory': stats['MemUsage'],
                            'pids': stats['PIDs'], 'network': stats['NetIO']})
            time.sleep(2)
        process.wait(timeout=10)
        assert process.returncode == 0, 'CONTAINER_COMMAND_FAILED'
    assert (E / 'result.json').is_file()
    result['dependency_closure'] = json.loads((E / 'result.json').read_text())['dependency_closure']
except BaseException as error:
    result['error'] = type(error).__name__ + ': ' + str(error)
finally:
    cleanup_errors = []
    if created:
        try:
            stopped = subprocess.run(['docker', 'stop', '--time', '5', name], capture_output=True, timeout=15)
            result['stop_returncode'] = stopped.returncode
        except BaseException as error:
            cleanup_errors.append('stop: ' + repr(error))
        try:
            result['container_state'] = json.loads(cmd(['docker', 'inspect', name, '--format', '{{json .State}}']))
            assert not result['container_state']['Running'], 'OWNED_CONTAINER_STILL_RUNNING'
        except BaseException as error:
            cleanup_errors.append('state: ' + repr(error))
    if process and process.poll() is None:
        try:
            process.wait(timeout=10)
        except BaseException as error:
            cleanup_errors.append('attach_wait: ' + repr(error))
    if cleanup_errors:
        result['cleanup_errors'] = cleanup_errors
        result.setdefault('error', 'TERMINAL_CLEANUP_UNVERIFIED')
    result['elapsed'] = time.monotonic() - started
    result['resource_samples'] = samples
    result['container_removed'] = False
    (E / 'host-result.json').write_text(json.dumps(result, indent=2))
assert not result.get('error'), result.get('error')
