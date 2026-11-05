"""Check active APT source hosts; comments are not network destinations."""
from pathlib import Path
import re


def active_hosts(text):
    active = '\n'.join(line.split('#', 1)[0] for line in text.splitlines())
    return set(re.findall(r'https?://([^/\s]+)', active))


allowed = {'deb.debian.org', 'security.debian.org'}
# Exercise this exact selector before interpreting the real image configuration.
assert active_hosts('# http://snapshot.debian.org/archive/debian/date\nURIs: http://deb.debian.org/debian\n') == {'deb.debian.org'}
assert active_hosts('deb https://security.debian.org/debian-security bookworm main # https://comment.invalid\n') == {'security.debian.org'}
assert active_hosts('URIs: https://unexpected.invalid/debian\n') - allowed == {'unexpected.invalid'}
print('ACTIVE_APT_SOURCE_FIXTURES_PASS', flush=True)
files = [p for p in Path('/etc/apt').rglob('*') if p.is_file() and p.suffix in ('.list', '.sources')]
hosts = active_hosts('\n'.join(p.read_text() for p in files))
print('ACTIVE_APT_HOSTS', sorted(hosts), flush=True)
assert hosts and hosts <= allowed, hosts
