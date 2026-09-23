"""Root-only, explicit Nginx provisioning for the enrolled Ubuntu lab account.

Installs Ubuntu's Nginx package with its existing/default configuration, validates
it, enables its service, and authorizes only exact Nginx maintenance commands.
Never overwrites site configuration or grants a general root shell.
"""
import json
import os
import pwd
import re
import stat
import subprocess
import tempfile
import urllib.request
from pathlib import Path


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run as root')
    policy_path = Path('/etc/evesdropctl-host-scripts.json')
    metadata = policy_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError('Unsafe host policy')
    policy = json.loads(policy_path.read_text())
    if policy.get('enabled') is not True or policy.get('environment') not in {'development', 'disposable_lab'}:
        raise RuntimeError('Host execution must be enabled for a lab account')
    account = pwd.getpwuid(policy['uid'])
    if account.pw_uid == 0 or not re.fullmatch(r'[a-z_][a-z0-9_-]*', account.pw_name):
        raise RuntimeError('Invalid lab account')
    if 'ID=ubuntu' not in Path('/etc/os-release').read_text().splitlines():
        raise RuntimeError('This provisioning script is for Ubuntu only')
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'DEBIAN_FRONTEND': 'noninteractive', 'LC_ALL': 'C'}

    def run(argv, timeout=180):
        return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, env=environment, timeout=timeout)

    run(['/usr/bin/apt-get', 'update'])
    run(['/usr/bin/apt-get', 'install', '-y', 'nginx'])
    run(['/usr/sbin/nginx', '-t'], 20)
    run(['/usr/bin/systemctl', 'enable', '--now', 'nginx'], 30)
    run(['/usr/bin/systemctl', 'is-active', '--quiet', 'nginx'], 10)
    # No proxy environment: verify the local packaged HTTP endpoint directly.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1/', timeout=5) as response:
        if response.status != 200:
            raise RuntimeError('Local HTTP verification failed')
    commands = ['/usr/bin/apt-get install -y nginx', '/usr/sbin/nginx -t',
                '/usr/bin/systemctl enable --now nginx', '/usr/bin/systemctl start nginx',
                '/usr/bin/systemctl reload nginx', '/usr/bin/systemctl restart nginx']
    rule = '# Exact Nginx commands for the enrolled lab account. No general sudo.\n'
    rule += account.pw_name + ' ALL=(root) NOPASSWD: ' + ', '.join(commands) + '\n'
    target = Path('/etc/sudoers.d/evesdropctl-nginx')
    if target.exists() or target.is_symlink():
        raise RuntimeError('Existing Nginx sudo policy requires manual review')
    fd, temporary = tempfile.mkstemp(prefix='.evesdropctl-', dir='/etc/sudoers.d')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(rule)
        os.chmod(temporary, 0o440)
        run(['/usr/sbin/visudo', '-cf', temporary], 10)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('Nginx config valid, service active, localhost HTTP 200; exact Nginx sudo commands installed.')


if __name__ == '__main__':
    main()
