FROM python@sha256:6b8555b2ad1d98bac702ce5bf226c41566408d87efde45b19cbdef9f36fcc998
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
RUN set -eu; test "$(. /etc/os-release; echo "$VERSION_CODENAME")" = bookworm; \
    grep -RhE 'https?://' /etc/apt/sources.list /etc/apt/sources.list.d/ || true
RUN python -c "import pathlib,re; rows='\n'.join(p.read_text() for p in pathlib.Path('/etc/apt').rglob('*') if p.is_file() and p.suffix in ('.list','.sources')); hosts=re.findall(r'https?://([^/\s]+)',rows); print(hosts); assert hosts and set(hosts)<= {'deb.debian.org','security.debian.org'}"
RUN set -eu; \
    apt-get update; \
    apt-cache policy pandoc graphviz gsfonts; \
    apt-get install -y --no-install-recommends pandoc graphviz gsfonts git make; \
    pandoc --version; dot -V; git --version; make --version; \
    dpkg -L fonts-urw-base35 | grep -E '\.(otf|t1|pfb)$'; \
    dpkg-query -W pandoc graphviz gsfonts fonts-urw-base35 git make
WORKDIR /work
