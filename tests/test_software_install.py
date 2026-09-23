import json
import sqlite3
from types import SimpleNamespace

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError
from test_authority import AuditCapture, arm, host
from test_host_scripts import client_setup
from test_mcp_execution import TestBridge, pair

from sysadmin_mcp import software_runtime as runtime
from sysadmin_mcp.authority import AuthorityService
from sysadmin_mcp.dynamic_execution import DynamicDenied, HostDraftRequest, HostScripts, Scripts
from sysadmin_mcp.host_scripts import HostJobs
from sysadmin_mcp.server import create_mcp_server
from sysadmin_mcp.software_install import InstallRequest


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['guided', 'autonomous_lab'])
@pytest.mark.parametrize('product,version', [('nginx', '1.24.0'), ('tomcat', '9.0.110')])
async def test_install_mcp_requires_human_approval_and_cannot_replay(tmp_path, mode, product, version):
    client, headers, password, _, calls, executor = client_setup(tmp_path, mode)
    server = create_mcp_server(executor, execution_bridge=TestBridge(client, pair(client, headers)))
    result = await server.call_tool('prepare_software_install', {
        'host': 'lab', 'product': product, 'target_version': version})
    job = result.structured_content
    assert job['approval_required'] and not calls
    assert job['scripts']['timeout_seconds'] == 900
    assert 'install(' in job['scripts']['script']
    assert 'verify(' in job['scripts']['verification']
    HostScripts.model_validate(job['scripts'])
    args = {'job_id': job['id'], 'digest': job['digest']}
    with pytest.raises(ToolError, match='operator review'):
        await server.call_tool('run_host_script', args)
    endpoint = '/api/scripts/jobs/' + job['id'] + '/run'
    assert client.post(endpoint, headers=headers, json={
        'digest': job['digest'], 'password': 'wrong'}).status_code == 401
    assert client.post(endpoint, headers=headers, json={
        'digest': '0' * 64, 'password': password}).status_code == 400
    assert client.post(endpoint, json={
        'digest': job['digest'], 'password': password}).status_code == 403
    assert not calls
    approved = {'digest': job['digest'], 'password': password}
    response = client.post(endpoint, headers=headers, json=approved)
    assert response.json()['state'] == 'verified'
    assert len(calls) == 1
    assert client.post(endpoint, headers=headers, json=approved).status_code == 400
    evidence = await server.call_tool('get_host_script_job', {'job_id': job['id']})
    assert evidence.structured_content['result']['verification']['exit_status'] == 0


def test_install_api_scope_validation_and_stop(tmp_path):
    client, headers, password, _, calls, _ = client_setup(tmp_path, 'guided')
    body = {'host': 'lab', 'product': 'nginx', 'target_version': '1.24.0'}
    assert client.post('/api/software/jobs', json=body).status_code == 403
    for change in ({'product': 'mysql'}, {'target_version': 'latest'},
                   {'target_version': '1.2.3;reboot'}, {'operation': 'upgrade'}, {'deployment': 'podman'}):
        assert client.post('/api/software/jobs', headers=headers, json={**body, **change}).status_code == 422
    assert client.post('/api/software/jobs', headers=headers,
                       json={**body, 'host': 'olaf-ubuntu'}).status_code == 400
    job = client.post('/api/software/jobs', headers=headers, json=body).json()
    client.post('/api/authority/stop', headers=headers)
    assert client.post('/api/scripts/jobs/' + job['id'] + '/run', headers=headers,
                       json={'digest': job['digest'], 'password': password}).status_code == 400
    assert not calls


def test_longer_host_jobs_do_not_widen_sandbox_limits():
    values = {'script': 'print(1)', 'verification': 'print(2)', 'timeout_seconds': 900}
    HostScripts(**values)
    with pytest.raises(ValidationError):
        Scripts(**values)
    with pytest.raises(ValidationError):
        HostScripts(**{**values, 'timeout_seconds': 901})
    with pytest.raises(ValidationError):
        InstallRequest(host='lab', product='tomcat', target_version='9.0.1\n')


@pytest.mark.parametrize('product', ['nginx', 'tomcat'])
def test_installer_orders_preflight_version_check_and_activation(monkeypatch, product):
    calls = []
    monkeypatch.setattr(runtime, 'preflight', lambda product: calls.append('preflight'))
    monkeypatch.setattr(runtime, 'package_version', lambda product: '1.2.3')
    def command(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout='installed', returncode=0)
    monkeypatch.setattr(runtime, 'command', command)
    runtime.install(product, '1.2.3')
    assert calls[0] == 'preflight'
    mutations = [argv for argv in calls if isinstance(argv, list) and argv[:3] == ['/usr/bin/sudo', '-n', '--']]
    assert mutations[0][-2:] == ['install', product + '-1.2.3']
    assert '--disablerepo=*' in mutations[0] and '--setopt=*.gpgcheck=1' in mutations[0]
    assert mutations[-1][-3:] == ['enable', '--now', product + '.service']


def test_wrong_installed_version_never_activates_service(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, 'preflight', lambda product: None)
    monkeypatch.setattr(runtime, 'package_version', lambda product: '9.9.9')
    monkeypatch.setattr(runtime, 'command', lambda argv, **kw: calls.append(argv) or SimpleNamespace(stdout='', returncode=0))
    with pytest.raises(RuntimeError, match='does not match'):
        runtime.install('nginx', '1.2.3')
    assert not any(argv[:3] == ['/usr/bin/sudo', '-n', '--'] and 'enable' in argv for argv in calls)


def test_preflight_failure_never_runs_install(monkeypatch):
    monkeypatch.setattr(runtime.platform, 'freedesktop_os_release', lambda: {'ID': 'ubuntu', 'VERSION_ID': '24.04'})
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: pytest.fail('No commands on wrong OS'))
    with pytest.raises(RuntimeError, match='Rocky Linux 9'):
        runtime.install('tomcat', '9.0.110')


def test_existing_install_is_refused_before_mutation(monkeypatch):
    monkeypatch.setattr(runtime.platform, 'freedesktop_os_release', lambda: {'ID': 'rocky', 'VERSION_ID': '9.6'})
    monkeypatch.setattr(runtime.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(runtime.os, 'access', lambda *args: True)
    monkeypatch.setattr(runtime.Path, 'is_dir', lambda path: True)
    monkeypatch.setattr(runtime, 'package_version', lambda product: '1.2.3')
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: pytest.fail('No commands on existing install'))
    with pytest.raises(RuntimeError, match='Already installed'):
        runtime.install('nginx', '1.2.3')


@pytest.mark.parametrize('active', [True, False])
def test_verifier_observes_service_state_independently(monkeypatch, capsys, active):
    monkeypatch.setattr(runtime, 'package_version', lambda product: '9.0.110')
    monkeypatch.setattr(runtime, 'http_ready', lambda product: True)
    monkeypatch.setattr(runtime.Path, 'is_dir', lambda path: True)
    def command(argv, **kwargs):
        output = 'enabled' if 'is-enabled' in argv else ('active' if active else 'failed') if 'is-active' in argv else '123'
        return SimpleNamespace(stdout=output, returncode=0)
    monkeypatch.setattr(runtime, 'command', command)
    runtime.verify('tomcat', '9.0.110')
    checks = json.loads(capsys.readouterr().out)['checks']
    assert all(c['passed'] for c in checks) is active


@pytest.mark.parametrize('product,status,expected', [('nginx', 200, True), ('nginx', 404, False),
                                                   ('tomcat', 404, True), ('tomcat', 500, False)])
def test_http_health_semantics(monkeypatch, product, status, expected):
    connection = SimpleNamespace(request=lambda *a: None, close=lambda: None,
                                 getresponse=lambda: SimpleNamespace(status=status))
    monkeypatch.setattr(runtime.http.client, 'HTTPConnection', lambda *a, **kw: connection)
    assert runtime.http_ready(product) is expected


@pytest.mark.parametrize('failure', ['existing_config', 'symlink', 'occupied_port', 'low_disk',
                                   'existing_unit', 'missing_tool', 'wrong_arch'])
def test_preflight_refuses_unsafe_host_before_any_privileged_command(monkeypatch, failure):
    monkeypatch.setattr(runtime.platform, 'freedesktop_os_release', lambda: {'ID': 'rocky', 'VERSION_ID': '9.6'})
    monkeypatch.setattr(runtime.platform, 'machine', lambda: 's390x' if failure == 'wrong_arch' else 'x86_64')
    monkeypatch.setattr(runtime.os, 'access', lambda *args: failure != 'missing_tool')
    monkeypatch.setattr(runtime.Path, 'is_dir', lambda path: True)
    monkeypatch.setattr(runtime.Path, 'exists', lambda path: failure == 'existing_config')
    monkeypatch.setattr(runtime.Path, 'is_symlink', lambda path: failure == 'symlink')
    monkeypatch.setattr(runtime, 'package_version', lambda product: None)
    monkeypatch.setattr(runtime.shutil, 'disk_usage', lambda root: SimpleNamespace(free=0 if failure == 'low_disk' else 2 ** 40))
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        if argv[0] == '/usr/bin/systemctl':
            return SimpleNamespace(stdout='loaded' if failure == 'existing_unit' else 'not-found')
        return SimpleNamespace(stdout='LISTEN 0 128 *:80 *:*' if failure == 'occupied_port' else '')
    monkeypatch.setattr(runtime, 'command', command)
    with pytest.raises(RuntimeError):
        runtime.install('nginx', '1.24.0')
    assert not any('/usr/bin/sudo' in argv for argv in calls)


@pytest.mark.parametrize('stage', ['sudo_permission', 'dnf', 'syntax', 'activation'])
def test_failure_stops_without_retry_or_later_mutations(monkeypatch, stage):
    monkeypatch.setattr(runtime, 'preflight', lambda product: None)
    monkeypatch.setattr(runtime, 'package_version', lambda product: '1.24.0')
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        actual = ('sudo_permission' if '-l' in argv else 'dnf' if '/usr/bin/dnf' in argv
                  else 'syntax' if '/usr/sbin/nginx' in argv else 'activation')
        if actual == stage:
            raise RuntimeError('simulated ' + stage + ' failure')
        return SimpleNamespace(stdout='')
    monkeypatch.setattr(runtime, 'command', command)
    with pytest.raises(RuntimeError, match='simulated'):
        runtime.install('nginx', '1.24.0')
    mutations = [argv for argv in calls if '-l' not in argv]
    assert len(mutations) == {'sudo_permission': 0, 'dnf': 1, 'syntax': 2, 'activation': 3}[stage]


@pytest.mark.asyncio
async def test_existing_job_database_migrates_and_legacy_jobs_still_require_approval(tmp_path):
    path = tmp_path / 'legacy.db'
    with sqlite3.connect(path) as db:
        db.execute('''CREATE TABLE dynamic_jobs (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, session TEXT NOT NULL,
            host TEXT NOT NULL, lease TEXT NOT NULL, expires TEXT NOT NULL,
            title TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL,
            state TEXT NOT NULL, result TEXT NOT NULL DEFAULT '{}')''')
    audit = AuditCapture()
    hosts = {'lab': host('lab', 'development')}
    authority = AuthorityService(hosts, audit)
    arm(authority, mode='autonomous_lab', capabilities=['host_scripts'])
    calls = []
    async def runner(*args):
        calls.append(args)
        output = {'exit_status': 0, 'stdout': '', 'stderr': '', 'truncated': False}
        return {'execution': output, 'verification': {**output, 'stdout':
            '{"checks":[{"name":"simulated check","passed":true}]}'}}
    jobs = HostJobs(path, authority, audit, runner, lambda: hosts)
    job = jobs.create('admin', 'session-a', HostDraftRequest(host='lab', title='legacy',
        script='print(1)', verification='print(2)'), approval_required=False)
    assert job['approval_required'] == 1
    with sqlite3.connect(path) as db:
        # Simulate an existing prepared job predating the approval column.
        db.execute('UPDATE dynamic_jobs SET approval_required=0 WHERE id=?', (job['id'],))
    with pytest.raises(DynamicDenied, match='approval'):
        await jobs.run('admin', 'session-a', job['id'], job['digest'])
    assert not calls
    completed = await jobs.run('admin', 'session-a', job['id'], job['digest'], user_approved=True)
    assert completed['state'] == 'verified' and len(calls) == 1
    # Reopening an already migrated database must not alter finished evidence.
    reopened = HostJobs(path, authority, audit, runner, lambda: hosts)
    assert reopened.get('admin', 'session-a', job['id'])['state'] == 'verified'
