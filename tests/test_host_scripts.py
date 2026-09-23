import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_authority import AuditCapture, arm, host
from test_web import FakeExecutor

from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.authority import AuthorityDenied, AuthorityService
from sysadmin_mcp.dynamic_execution import DraftRequest
from sysadmin_mcp.host_scripts import HostJobs, check_target
from sysadmin_mcp.web import AgentService, create_app


class Generator:
    def __init__(self):
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(output_text=json.dumps({
            "script": "print('inspect host')",
            "verification": "print('verification')",
        }))


def client_setup(tmp_path, mode):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    hosts = {"lab": host("lab", "development"), "olaf-ubuntu": host("olaf-ubuntu", "development")}
    generator, calls = Generator(), []

    async def runner(name, scripts):
        calls.append((name, scripts.script))
        output = {"exit_status": 0, "stdout": "observed", "stderr": "", "truncated": False}
        return {"execution": output, "verification": {**output,
                "stdout": '{"checks":[{"name":"observed service health","passed":true}]}'}}

    executor = FakeExecutor()
    service = AgentService(hosts, executor, client=SimpleNamespace(responses=generator))
    client = TestClient(create_app(service, audit, host_runner=runner))
    login = client.post('/api/auth/login', json={"username": "admin", "password": "admin"}).json()
    headers = {"x-csrf-token": login["csrf_token"]}
    password = "host-script-test-password"
    client.post('/api/auth/change-password', headers=headers,
                json={"current_password": "admin", "new_password": password})
    response = client.post('/api/authority/arm', headers=headers, json={
        "mode": mode, "hosts": ["lab"], "capabilities": ["host_scripts"],
        "duration_minutes": 15, "action_budget": 1, "concurrency": 1, "password": password})
    assert response.status_code == 200, response.text
    return client, headers, password, generator, calls, executor


def chat(client, headers, message="inspect service", selected="lab"):
    response = client.post('/api/chat', headers=headers, json={"host": selected, "message": message})
    assert response.status_code == 200
    return [json.loads(line) for line in response.text.splitlines()]


def test_guided_chat_prepares_without_execution_then_requires_password(tmp_path):
    client, headers, password, generator, calls, executor = client_setup(tmp_path, 'guided')
    events = chat(client, headers)
    summary = next(e['message'] for e in events if e['type'] == 'summary')
    job_id = summary.split('/scripts?job=')[1].split(')')[0]
    assert calls == [] and executor.hosts == []
    assert 'ON THE HOST' in generator.calls[0]['instructions']
    job = client.get('/api/scripts/jobs/' + job_id).json()
    endpoint = '/api/scripts/jobs/' + job_id + '/run'
    assert client.post(endpoint, headers=headers, json={"digest": job['digest'], "password": "bad"}).status_code == 401
    assert client.post(endpoint, json={"digest": job['digest'], "password": password}).status_code == 403
    response = client.post(endpoint, headers=headers, json={"digest": job['digest'], "password": password})
    assert response.json()['state'] == 'verified'
    assert calls == [('lab', "print('inspect host')")]
    assert client.post(endpoint, headers=headers, json={"digest": job['digest'], "password": password}).status_code == 400


def test_autonomous_chat_waits_for_approval_then_executes_once(tmp_path):
    client, headers, password, _, calls, executor = client_setup(tmp_path, 'autonomous_lab')
    events = chat(client, headers)
    summary = next(e['message'] for e in events if e['type'] == 'summary')
    job_id = summary.split('/scripts?job=')[1].split(')')[0]
    assert not calls
    job = client.get('/api/scripts/jobs/' + job_id).json()
    assert job['approval_required']
    response = client.post('/api/scripts/jobs/' + job_id + '/run', headers=headers,
                           json={'digest': job['digest'], 'password': password})
    assert response.json()['state'] == 'verified'
    assert len(calls) == 1 and not executor.hosts
    client.post('/api/scripts/jobs/' + job_id + '/run', headers=headers,
                json={'digest': job['digest'], 'password': password})
    assert len(calls) == 1


@pytest.mark.parametrize('mode', ['guided', 'autonomous_lab'])
def test_target_mismatch_and_pause_never_generate_or_execute(tmp_path, mode):
    client, headers, _, generator, calls, _ = client_setup(tmp_path, mode)
    events = chat(client, headers, 'install nginx on olaf')
    assert any(e['type'] == 'error' and 'Selected VM' in e['message'] for e in events)
    events = chat(client, headers, selected='olaf-ubuntu')
    assert any(e['type'] == 'error' for e in events)
    client.post('/api/authority/pause', headers=headers)
    assert any(e['type'] == 'error' for e in chat(client, headers))
    assert not generator.calls and not calls


def test_host_scripts_never_allow_production_or_sandbox(tmp_path):
    audit = AuditCapture()
    hosts = {'lab': host('lab', 'production')}
    authority = AuthorityService(hosts, audit)
    for mode in ['guided', 'autonomous_lab', 'dynamic_sandbox']:
        with pytest.raises(AuthorityDenied):
            arm(authority, mode=mode, capabilities=['host_scripts'])
    hosts['lab'] = replace(hosts['lab'], environment='development')
    authority.replace_hosts(hosts)
    arm(authority, mode='guided', capabilities=['host_scripts'])
    jobs = HostJobs(tmp_path / 'jobs.db', authority, audit, None, lambda: hosts)
    hosts['lab'] = replace(hosts['lab'], environment='production')
    with pytest.raises(AuthorityDenied):
        jobs.create('admin', 'session-a', DraftRequest(host='lab', title='test', script='print(1)', verification='print(2)'))


def test_target_detection_keeps_shared_prefix_and_selected_host():
    hosts = {'lab-1': host('lab-1', 'development'), 'lab-2': host('lab-2', 'development')}
    check_target('inspect lab-1', 'lab-1', hosts)
    with pytest.raises(AuthorityDenied):
        check_target('inspect lab-2', 'lab-1', hosts)


@pytest.mark.asyncio
@pytest.mark.parametrize('exit_status', [0, 1])
async def test_host_helper_separates_verification_and_stops_after_failure(monkeypatch, exit_status):
    from sysadmin_mcp import host_script_helper
    from sysadmin_mcp.dynamic_execution import Output, Scripts

    calls = []

    async def process(argv, source, **kwargs):
        calls.append((argv, source, kwargs))
        return Output(exit_status=exit_status, stdout='evidence', stderr='', truncated=False)

    monkeypatch.setattr(host_script_helper, 'bounded_process', process)
    result = await host_script_helper.execute(Scripts(script='print(1)', verification='print(2)'))
    assert len(calls) == (2 if exit_status == 0 else 1)
    assert calls[0][1] == 'print(1)' and calls[0][2]['process_group'] is True
    if exit_status == 0:
        assert calls[1][1] == 'print(2)'
        assert calls[0][2]['cwd'] == calls[1][2]['cwd']
    else:
        assert result.verification is None


def test_host_policy_is_opt_in_nonroot_and_exact_uid(tmp_path, monkeypatch):
    from sysadmin_mcp import host_script_helper

    policy = tmp_path / 'policy.json'
    monkeypatch.setattr(host_script_helper, 'POLICY', str(policy))
    monkeypatch.setattr(host_script_helper, 'validate_policy_file', lambda path: None)
    monkeypatch.setattr(host_script_helper.os, 'geteuid', lambda: 1001, raising=False)
    for body in [{"enabled": False, "environment": 'development', "uid": 1001},
                 {"enabled": True, "environment": 'production', "uid": 1001},
                 {"enabled": True, "environment": 'development', "uid": 1002}]:
        policy.write_text(json.dumps(body))
        with pytest.raises(ValueError):
            host_script_helper.load_policy()
    policy.write_text(json.dumps({"enabled": True, "environment": 'development', "uid": 1001}))
    assert host_script_helper.load_policy()['uid'] == 1001
    monkeypatch.setattr(host_script_helper.os, 'geteuid', lambda: 0)
    with pytest.raises(ValueError):
        host_script_helper.load_policy()
