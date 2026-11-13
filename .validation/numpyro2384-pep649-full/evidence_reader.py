"""Shared bounded artifact/JUnit checks; fixtures exercise the production readers."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile


def run_identity(run, run_id, sha, workflow, branch):
    assert run['id'] == run_id and run['head_sha'] == sha
    assert run['path'] == workflow and run['head_branch'] == branch
    assert run['run_attempt'] == 1 and run['actor']['login'] == 'leninworld'


def archive_identity(artifact, run_id, sha, size, digest):
    assert artifact['workflow_run']['id'] == run_id
    assert artifact['workflow_run']['head_sha'] == sha and not artifact['expired']
    assert artifact['size_in_bytes'] == size and 0 < size <= 96 * 1024**2
    assert artifact['digest'] == 'sha256:' + digest


def junit_counts(path):
    cases = list(ET.parse(path).iter('testcase'))
    result = {'total': len(cases),
              'failed': sum(c.find('failure') is not None for c in cases),
              'errors': sum(c.find('error') is not None for c in cases),
              'skipped': sum(c.find('skipped') is not None for c in cases)}
    result['passed'] = result['total'] - sum(result[k] for k in ('failed', 'errors', 'skipped'))
    assert result['passed'] >= 0
    return result


def safe_members(archive):
    members = archive.infolist()
    assert len(members) <= 10000 and sum(x.file_size for x in members) <= 500 * 1024**2
    names = set()
    for item in members:
        path = PurePosixPath(item.filename)
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename
        assert path.parts and str(path) not in names
        names.add(str(path))
        mode = stat.S_IFMT(item.external_attr >> 16)
        assert mode in (0, stat.S_IFREG, stat.S_IFDIR)
        assert item.file_size <= 64 * 1024**2
    return members


def fixtures(positive, negative):
    assert junit_counts(positive) == {'total': 3, 'failed': 0, 'errors': 0, 'skipped': 0, 'passed': 3}
    counts = junit_counts(negative)
    assert counts['failed'] == 1 and counts['errors'] == 1 and counts['passed'] == 0
    run = {'id': 7, 'head_sha': 'a'*40, 'path': '.github/workflows/exact.yml',
           'head_branch': 'fixture', 'run_attempt': 1, 'actor': {'login': 'leninworld'}}
    run_identity(run, 7, 'a'*40, '.github/workflows/exact.yml', 'fixture')
    rejected = []
    for key, value in [('head_sha', 'b'*40), ('run_attempt', 2), ('actor', {'login': 'other'})]:
        changed = dict(run, **{key: value})
        try: run_identity(changed, 7, 'a'*40, '.github/workflows/exact.yml', 'fixture')
        except AssertionError: rejected.append(key)
        else: raise AssertionError('Run identity fixture accepted ' + key)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z: z.writestr('actual-pytest.xml', Path(positive).read_bytes())
    raw = stream.getvalue(); digest = hashlib.sha256(raw).hexdigest()
    artifact = {'workflow_run': {'id': 7, 'head_sha': 'a'*40}, 'expired': False,
                'size_in_bytes': len(raw), 'digest': 'sha256:' + digest}
    archive_identity(artifact, 7, 'a'*40, len(raw), digest)
    with zipfile.ZipFile(io.BytesIO(raw)) as z: assert len(safe_members(z)) == 1
    for name, size, sha in [('size', len(raw)-1, digest), ('digest', len(raw), '0'*64)]:
        try: archive_identity(artifact, 7, 'a'*40, size, sha)
        except AssertionError: rejected.append(name)
        else: raise AssertionError('Archive identity fixture accepted ' + name)
    try:
        with zipfile.ZipFile(io.BytesIO(raw[:-8])) as z: safe_members(z)
    except zipfile.BadZipFile: rejected.append('truncated-zip')
    else: raise AssertionError('Truncated archive accepted')
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, 'w') as z: z.writestr('../escape.xml', b'fixture')
    try:
        with zipfile.ZipFile(bad) as z: safe_members(z)
    except AssertionError: rejected.append('unsafe-path')
    else: raise AssertionError('Unsafe archive path accepted')
    print(json.dumps({'actualPytestXML': True, 'realZipRoundtrip': True, 'rejected': rejected}))


if __name__ == '__main__':
    assert len(sys.argv) == 4 and sys.argv[1] == '--fixtures'
    fixtures(sys.argv[2], sys.argv[3])
