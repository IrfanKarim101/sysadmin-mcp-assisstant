import json
from types import SimpleNamespace

import pytest
from openai import APIConnectionError, APIStatusError
from test_host_scripts import client_setup

from sysadmin_mcp.script_generation import (
    SCRIPT_RESPONSE_FORMAT,
    GenerationOutputError,
    parse_script_response,
)

DRAFT = json.dumps({'script': 'print("task")', 'verification': 'print("checks")'})


@pytest.mark.parametrize('content', [DRAFT, '\n```json\n' + DRAFT + '\n```\n', '```\n' + DRAFT + '\n```'])
def test_accepts_plain_or_single_fenced_json_without_changing_code(content):
    assert parse_script_response(content).script == 'print("task")'


@pytest.mark.parametrize(('content', 'reason', 'message'), [
    (DRAFT, 'length', 'truncated'), ('', 'stop', 'empty'),
    ('', 'content_filter', 'declined'), ('Here is JSON: ' + DRAFT, 'stop', 'malformed JSON'),
    ('```python\nprint(1)\n```', 'stop', 'malformed JSON'),
    (json.dumps({'script': 'invalid syntax !', 'verification': 'print(1)'}), 'stop', 'syntax'),
    ('x' * 80001, 'stop', 'response limit'),
], ids=['truncated', 'empty', 'refused', 'prose', 'python-fence', 'syntax', 'oversize'])
def test_invalid_or_incomplete_drafts_never_become_executable(content, reason, message):
    with pytest.raises(GenerationOutputError, match=message):
        parse_script_response(content, reason)


def fake_provider(monkeypatch, response=None, error=None):
    from sysadmin_mcp import web

    requests = []

    class Client:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def create(self, **kwargs):
            requests.append(kwargs)
            if error:
                raise error
            return response

    monkeypatch.setattr(web, 'AsyncOpenAI', Client)
    monkeypatch.setenv('GEMINI_API_KEY', 'test-only')
    return requests


def test_gemini_generation_requests_schema_and_accepts_framed_response(tmp_path, monkeypatch):
    response = SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content='```json\n' + DRAFT + '\n```'))])
    requests = fake_provider(monkeypatch, response=response)
    client, headers, _, _, calls, _ = client_setup(tmp_path, 'guided')
    result = client.post('/api/scripts/generate', headers=headers,
                         json={'host': 'lab', 'task': 'enable nginx', 'provider': 'gemini'})
    assert result.status_code == 200
    assert result.json()['script'] == 'print("task")'
    assert requests[0]['response_format'] == SCRIPT_RESPONSE_FORMAT
    assert not calls


@pytest.mark.parametrize(('error', 'status', 'message'), [
    (TimeoutError(), 504, 'timed out'),
    (APIConnectionError(request=SimpleNamespace(url='https://example.test')), 502, 'Cannot connect'),
    (APIStatusError('private upstream details', response=SimpleNamespace(status_code=429, headers={}, request=SimpleNamespace(url='https://example.test')), body=None), 502, 'quota'),
])
def test_generation_errors_identify_provider_failure_without_leaking_details(tmp_path, monkeypatch, error, status, message):
    fake_provider(monkeypatch, error=error)
    client, headers, _, _, calls, _ = client_setup(tmp_path, 'guided')
    response = client.post('/api/scripts/generate', headers=headers,
                           json={'host': 'lab', 'task': 'enable nginx', 'provider': 'gemini'})
    assert response.status_code == status
    assert message in response.json()['detail']
    assert 'private upstream details' not in response.text
    assert not calls
