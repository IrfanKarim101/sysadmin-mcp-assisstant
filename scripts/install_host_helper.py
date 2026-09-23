"""Run as root on an enrolled lab VM from a reviewed copy of this repository.

Installs host-script execution for one existing unprivileged account. Does not
change SSH configuration or grant sudo permission to generated scripts.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    import pwd

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user', required=True)
    parser.add_argument('--environment', choices=['development', 'disposable_lab'], required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.version_info < (3, 11):
        parser.error('Run using root and Python 3.11 or newer')
    account = pwd.getpwnam(args.user)
    if account.pw_uid == 0:
        parser.error('Select a nonroot SSH account')
    source = Path(__file__).resolve().parents[1] / 'src' / 'sysadmin_mcp'
    required = ['__init__.py', 'audit.py', 'authority.py', 'config.py', 'models.py',
                'dynamic_execution.py', 'dynamic_sandbox.py', 'forced_command.py',
                'host_script_helper.py', 'dynamic_gate.py']
    if not all((source / name).is_file() for name in required):
        parser.error('Run from the complete reviewed repository')
    root = Path('/opt/evesdropctl-host')
    launcher = Path('/usr/local/bin/sysadmin-host-scripts')
    policy = Path('/etc/evesdropctl-host-scripts.json')
    if any(path.exists() or path.is_symlink() for path in (root, launcher, policy)):
        parser.error('An installation already exists; review an upgrade instead of overwriting it')
    os.umask(0o022)
    root.mkdir(mode=0o755)
    subprocess.run([sys.executable, '-m', 'venv', str(root / 'venv')], check=True)
    python = str(root / 'venv/bin/python')
    subprocess.run([python, '-m', 'pip', 'install', 'pydantic>=2,<3'], check=True)
    library = root / 'lib/sysadmin_mcp'
    library.mkdir(parents=True, mode=0o755)
    for name in required:
        shutil.copyfile(source / name, library / name)
        (library / name).chmod(0o644)
    launcher.write_text(f'#!{python} -I\nimport sys\nsys.path.insert(0, "{root}/lib")\n'
                        'from sysadmin_mcp.host_script_helper import main\nraise SystemExit(main())\n')
    launcher.chmod(0o755)
    runtime = Path('/run/evesdropctl-host-scripts')
    runtime.mkdir(mode=0o755, exist_ok=True)
    if runtime.is_symlink() or runtime.stat().st_uid != 0 or runtime.stat().st_mode & 0o022:
        raise RuntimeError('Unsafe runtime parent directory')
    user_runtime = runtime / str(account.pw_uid)
    if user_runtime.is_symlink():
        raise RuntimeError('Unsafe runtime directory')
    user_runtime.mkdir(mode=0o700, exist_ok=True)
    os.chown(user_runtime, account.pw_uid, account.pw_gid)
    user_runtime.chmod(0o700)
    Path('/etc/tmpfiles.d/evesdropctl-host-scripts.conf').write_text(
        'd /run/evesdropctl-host-scripts 0755 root root -\n'
        f'd {user_runtime} 0700 {account.pw_uid} {account.pw_gid} -\n')
    # Enable only after installation and runtime setup have succeeded.
    policy.write_text(json.dumps({"enabled": True, "environment": args.environment, "uid": account.pw_uid}) + '\n')
    policy.chmod(0o644)
    print('Installed host helper. SSH permissions and sudo policy were not changed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
