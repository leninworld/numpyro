import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib

W = Path('/work')
E = W / 'evidence'
E.mkdir(exist_ok=True)
M = json.loads(Path('/inputs/manifest.json').read_text())
ENV = dict(os.environ, PYTHONPATH='/work/tool')
UV = [sys.executable, '-m', 'uv']


def run(name, argv, cwd=W, timeout=300, env=ENV):
    with (E / (name + '.log')).open('wb') as f:
        subprocess.run(argv, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT,
                       timeout=timeout, check=True)
    return (E / (name + '.log')).read_text()


def requirements(config, groups, git_pin=None):
    values = list(config['project'].get('dependencies', []))
    values += config['project'].get('optional-dependencies', {}).get('cpu', [])
    for group in groups:
        rows = config['dependency-groups'][group]
        assert all(isinstance(v, str) and '\n' not in v for v in rows)
        values += rows
    if git_pin:
        assert config['tool']['uv']['sources']['funsor']['git'] == 'https://github.com/pyro-ppl/funsor.git'
        values = [('funsor @ git+https://github.com/pyro-ppl/funsor.git@' + git_pin)
                  if v == 'funsor' or v.startswith('funsor>=') else v for v in values]
    assert all('\n' not in v and not v.startswith('-') for v in values)
    return values


assert sys.version_info[:2] == (3, 12)
for directory in ('home', 'tmp', 'uv-cache', 'tool'):
    (W / directory).mkdir(exist_ok=True)
system = {k: shutil.which(k) for k in ('git', 'pandoc', 'dot', 'fc-list')}
(E / 'system-tools.json').write_text(json.dumps(system, indent=2))
assert system['git'], 'Required Git executable absent; no bootstrap fallback'
run('bootstrap', [sys.executable, '-m', 'pip', 'install', '--no-deps', '--require-hashes',
                  '--target', '/work/tool', '-r', '/inputs/bootstrap.txt'], timeout=180)
assert re.fullmatch(r'uv 0\.11\.8(?: \(.+\))?', run('uv-version', UV + ['--version']).strip())
help_text = run('compile-help', UV + ['pip', 'compile', '--help'])
assert all(x in help_text for x in ('--python-version', '--python-platform', '--constraint', '--generate-hashes'))

# Exercise the actual group extractor, a local Git source, output paths and logs
# before resolving the real dependency graph. No NumPyro imports or tests run.
D = W / 'fixture-dependency'
D.mkdir()
(D / 'closure_fixture').mkdir()
(D / 'closure_fixture/__init__.py').write_text('')
(D / 'pyproject.toml').write_text('[build-system]\nrequires=["setuptools>=61"]\nbuild-backend="setuptools.build_meta"\n[project]\nname="closure-fixture"\nversion="0.1.0"\n')
run('fixture-init', ['git', 'init', '--quiet', str(D)])
run('fixture-add', ['git', '-C', str(D), 'add', '.'])
run('fixture-commit', ['git', '-C', str(D), '-c', 'user.name=Fixture', '-c',
                      'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'fixture'])
sha = run('fixture-sha', ['git', '-C', str(D), 'rev-parse', 'HEAD']).strip()
fixture = {'project': {'dependencies': []}, 'dependency-groups': {
    'test': ['closure-fixture @ git+file:///work/fixture-dependency@' + sha]}}
rows = requirements(fixture, ['test'])
assert len(rows) == 1 and sha in rows[0]
(W / 'fixture.in').write_text('\n'.join(rows) + '\n')
run('fixture-resolve', UV + ['pip', 'compile', '/work/fixture.in',
    '-c', '/inputs/constraints.txt', '--python-version', '3.12', '--python-platform',
    'aarch64-unknown-linux-gnu', '--generate-hashes', '-o', '/work/fixture.txt'], timeout=180)
assert sha in (W / 'fixture.txt').read_text()
run('fixture-venv', UV + ['venv', '/work/fixture-venv', '--python', sys.executable])
run('fixture-sync', UV + ['pip', 'sync', '--python', '/work/fixture-venv/bin/python',
    '/work/fixture.txt'])
run('fixture-check', UV + ['pip', 'check', '--python', '/work/fixture-venv/bin/python'])
assert sha in run('fixture-freeze', UV + ['pip', 'freeze', '--python', '/work/fixture-venv/bin/python'])
assert (E / 'fixture-resolve.log').is_file()
try:
    run('fixture-timeout', [sys.executable, '-u', '-c',
        'import time; print("timeout-fixture", flush=True); time.sleep(10)'], timeout=1)
except subprocess.TimeoutExpired:
    assert 'timeout-fixture' in (E / 'fixture-timeout.log').read_text()
else:
    raise AssertionError('TIMEOUT_FIXTURE_DID_NOT_TIMEOUT')
# Verify the archive exporter on a synthetic file, without extracting a cache.
fixture_archive = E / 'fixture.tar.gz'
with tarfile.open(fixture_archive, 'w:gz') as archive:
    archive.add(W / 'fixture.txt', arcname='fixture.txt')
with tarfile.open(fixture_archive, 'r:gz') as archive:
    assert archive.getnames() == ['fixture.txt']
    assert archive.extractfile('fixture.txt').read() == (W / 'fixture.txt').read_bytes()
(E / 'fixture-pass.json').write_text(json.dumps({'git_commit': sha, 'groups': ['test'],
    'timeout_and_log_pass': True, 'archive_export_pass': True, 'pass': True}))

# Fresh exact source metadata; do not check out, import or run project code.
source = W / 'source-metadata'
run('source-init', ['git', 'init', '--bare', str(source)])
for label, commit in M['source_commits'].items():
    run('source-fetch-' + label, ['git', '-C', str(source), 'fetch', '--depth=1',
        'https://github.com/pyro-ppl/numpyro.git', commit], timeout=90)
    tree = run('source-tree-' + label, ['git', '-C', str(source), 'ls-tree',
        '--name-only', commit])
    assert 'uv.lock' not in tree.splitlines(), 'LOCK_PRESENT_REQUIRES_NEW_LOCKED_PLAN'
    blob = run('source-pyproject-' + label, ['git', '-C', str(source), 'show',
        commit + ':pyproject.toml'])
    assert blob.encode() == Path('/inputs/pyproject.toml').read_bytes(), 'PYPROJECT_CHANGED'
run('source-overlap', ['git', '-C', str(source), 'diff', '--stat',
    M['source_commits']['published'], M['source_commits']['master'], '--',
    'numpyro/infer/util.py', 'test/infer/test_autoguide.py', 'test/infer/test_infer_util.py'])

config = tomllib.loads(Path('/inputs/pyproject.toml').read_text())
rows = requirements(config, M['groups'], M['funsor_pin'])
assert len(rows) == 51
(E / 'root-requirements.json').write_text(json.dumps(rows, indent=2))
(W / 'requirements.in').write_text('\n'.join(rows) + '\n')
run('resolve', UV + ['pip', 'compile', '/work/requirements.in', '-c', '/inputs/constraints.txt',
                    '--python-version', '3.12', '--python-platform', 'aarch64-unknown-linux-gnu',
                    '--generate-hashes', '-o', '/work/evidence/closure.txt'], timeout=420)
assert M['funsor_pin'] in (E / 'closure.txt').read_text()
run('venv', UV + ['venv', '/work/venv', '--python', sys.executable])
run('sync', UV + ['pip', 'sync', '--python', '/work/venv/bin/python', '/work/evidence/closure.txt'], timeout=420)
run('check', UV + ['pip', 'check', '--python', '/work/venv/bin/python'])
run('freeze', UV + ['pip', 'freeze', '--python', '/work/venv/bin/python'])
assert M['funsor_pin'] in (E / 'freeze.log').read_text()
cache = E / 'uv-cache.tar.gz'


class BoundedWriter:
    def __init__(self, stream):
        self.stream = stream
        self.count = 0

    def write(self, data):
        assert self.count + len(data) <= M['cache_artifact_cap'], 'CACHE_ARTIFACT_CAP'
        n = self.stream.write(data)
        self.count += n
        return n


with cache.open('wb') as stream:
    with tarfile.open(fileobj=BoundedWriter(stream), mode='w|gz', dereference=False) as archive:
        archive.add(W / 'uv-cache', arcname='uv-cache')
assert cache.stat().st_size <= M['cache_artifact_cap']
with tarfile.open(cache, 'r:gz') as archive:
    members = [{'name': x.name, 'size': x.size, 'type': x.type.decode('ascii'),
                'linkname': x.linkname} for x in archive]
(E / 'cache-members.json').write_text(json.dumps(members, indent=2))
inventory = {}
for f in E.iterdir():
    if f.is_file():
        h = hashlib.sha256()
        with f.open('rb') as stream:
            for b in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(b)
        inventory[f.name] = {'bytes': f.stat().st_size, 'sha256': h.hexdigest()}
(E / 'result.json').write_text(json.dumps({'dependency_closure': True, 'project_tests': False,
    'project_builds': False, 'cache_restore_safety': 'NOT_VERIFIED_NO_EXTRACTION',
    'system_tools': system, 'inventory': inventory}, indent=2))
