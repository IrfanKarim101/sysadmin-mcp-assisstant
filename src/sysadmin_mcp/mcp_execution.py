"""Restricted MCP delegation to the web application's armed execution session."""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, Request
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditEvent
from .authority import AuthorityDenied
from .dynamic_execution import DraftRequest, DynamicDenied
from .software_install import InstallRequest, prepare_install


class ReviewedJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def register_execution_api(app, auth, authority, jobs, audit, change_operator):
    # Raw web session credentials never leave this process. Tokens cannot arm,
    # approve Guided jobs, authenticate to other APIs, or outlive their lease.
    delegations = {}

    @app.post('/api/scripts/mcp-connection')
    async def pair(request: Request):
        from .auth import SESSION_COOKIE

        session = change_operator(request)
        state = authority.current()
        if not state['hosts']:
            raise HTTPException(400, 'Arm a host-script mode before connecting MCP')
        try:
            jobs.authorized(session.username, session.session_id, state['hosts'][0])
        except AuthorityDenied as error:
            raise HTTPException(400, str(error)) from error
        # One connection per authenticated session; regenerating revokes the old one.
        for key, record in list(delegations.items()):
            if record['session'] == session.session_id or record['lease'] != state['generation_id']:
                del delegations[key]
        token = secrets.token_urlsafe(32)
        audit.append(AuditEvent(request_id=str(uuid4()), session_id=session.session_id,
                                target_host='authority', tool_name='mcp_execution_delegated',
                                parameters={'mode': state['mode'], 'hosts': state['hosts']},
                                command=(), status='success'))
        delegations[hashlib.sha256(token.encode()).hexdigest()] = {
            'cookie': request.cookies.get(SESSION_COOKIE), 'session': session.session_id,
            'lease': state['generation_id'],
        }
        return {'token': token, 'expires_at': state['expires_at'],
                'mode': state['mode'], 'hosts': state['hosts']}

    def delegated(request):
        header = request.headers.get('authorization', '')
        token = header.removeprefix('Bearer ') if header.startswith('Bearer ') else ''
        record = delegations.get(hashlib.sha256(token.encode()).hexdigest())
        if not record:
            raise HTTPException(401, 'MCP connection is missing or revoked')
        session = auth.authenticate(record['cookie'])
        state = authority.current()
        if (session is None or session.must_change_password or session.role != 'administrator'
                or session.session_id != record['session'] or state['generation_id'] != record['lease']):
            raise HTTPException(401, 'MCP connection expired; connect again from the UI')
        if state['status'] != 'active':
            raise HTTPException(403, 'Execution authority is paused or inactive')
        return session, state

    @app.get('/api/mcp/scope')
    async def scope(request: Request):
        _, state = delegated(request)
        return {key: state[key] for key in ('mode', 'status', 'hosts', 'capabilities',
                                           'expires_at', 'action_budget', 'actions_used')}

    @app.post('/api/mcp/jobs')
    async def prepare(body: DraftRequest, request: Request):
        session, state = delegated(request)
        try:
            job = jobs.create(session.username, session.session_id, body)
        except (AuthorityDenied, DynamicDenied) as error:
            raise HTTPException(400, str(error)) from error
        return {**job, 'mode': state['mode'], 'review_path': f"/scripts?job={job['id']}",
                'next_step': 'Operator must approve in the web UI'}

    @app.post('/api/mcp/software/jobs')
    async def prepare_software(body: InstallRequest, request: Request):
        session, _ = delegated(request)
        try:
            return prepare_install(jobs, session, body)
        except (AuthorityDenied, DynamicDenied) as error:
            raise HTTPException(400, str(error)) from error

    @app.get('/api/mcp/jobs/{job_id}')
    async def get(job_id: UUID, request: Request):
        session, _ = delegated(request)
        try:
            return jobs.get(session.username, session.session_id, str(job_id))
        except DynamicDenied as error:
            raise HTTPException(404, str(error)) from error

    @app.post('/api/mcp/jobs/{job_id}/run')
    async def run(job_id: UUID, body: ReviewedJob, request: Request):
        delegated(request)
        raise HTTPException(403, 'Host execution requires operator review and approval in the web UI')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ToolError('Execution API redirects are not permitted')


class ExecutionBridge:
    def __init__(self, base_url, token):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}
                or parsed.username or parsed.password or parsed.path not in {'', '/'}
                or parsed.query or parsed.fragment):
            raise ValueError('Execution API must be a loopback HTTP origin')
        if not token:
            raise ValueError('Set SYSADMIN_MCP_EXECUTION_TOKEN from the Host scripts connection UI')
        self.base_url, self.token = base_url.rstrip('/'), token

    async def call(self, path, body=None):
        def request():
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            req = urllib.request.Request(self.base_url + '/api/mcp' + path,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers={'Authorization': 'Bearer ' + self.token,
                                                  'Content-Type': 'application/json'})
            try:
                with opener.open(req, timeout=160) as response:
                    raw = response.read(1_000_001)
                    if len(raw) > 1_000_000:
                        raise ToolError('Execution API response exceeded bounds')
                    return json.loads(raw)
            except urllib.error.HTTPError as error:
                try:
                    detail = json.loads(error.read(4096)).get('detail', 'Execution denied')
                except ValueError:
                    detail = 'Execution API request failed'
                raise ToolError(str(detail)) from None
            except (OSError, ValueError):
                raise ToolError('Execution API unavailable; inspect job status before retrying') from None
        return await asyncio.to_thread(request)


def register_mcp_execution_tools(server, bridge):
    read = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)
    prepare = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False)
    write = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False)

    @server.tool(annotations=prepare, structured_output=True)
    async def prepare_software_install(host: str, product: str, target_version: str) -> dict[str, Any]:
        """Prepare a native Nginx or Tomcat fresh install on an enrolled Rocky 9 lab VM.

        Use an exact upstream version available in the host's baseos/appstream repositories.
        Requires host_scripts authority and a provisioned host helper with sudo permissions.
        Return the review_path and summary to the user. Every installation requires the
        operator's approval in the web UI, even in Autonomous Lab mode. Never substitute
        a generic script to bypass this approval. Read results with get_host_script_job.
        """
        body = InstallRequest(host=host, product=product, target_version=target_version)
        return await bridge.call('/software/jobs', body.model_dump())

    @server.tool(annotations=read, structured_output=True)
    async def get_execution_scope() -> dict[str, Any]:
        """Check the operator-armed mode, exact hosts, capability and remaining job budget."""
        return await bridge.call('/scope')

    @server.tool(annotations=prepare, structured_output=True)
    async def prepare_host_script(host: str, title: str, script: str, verification: str,
                                  timeout_seconds: int = 120) -> dict[str, Any]:
        """Prepare generated Python and a separate verifier for the selected lab VM.

        Call get_execution_scope first. Preserve data and configuration; discover OS and
        current state before changes. Scripts run with the SSH account's permissions.
        Verification must independently inspect results and print JSON checks with name
        and strict boolean passed fields. No false success or automatic destructive retry.
        Return the review_path to the user in every mode; never approve your own script.
        After user approval and execution, inspect evidence with get_host_script_job.
        """
        body = DraftRequest(host=host, title=title, script=script, verification=verification,
                            timeout_seconds=timeout_seconds)
        return await bridge.call('/jobs', body.model_dump())

    @server.tool(annotations=read, structured_output=True)
    async def get_host_script_job(job_id: UUID) -> dict[str, Any]:
        """Read persisted execution output and verification evidence for an owned job."""
        return await bridge.call(f'/jobs/{job_id}')

    @server.tool(annotations=write, structured_output=True)
    async def run_host_script(job_id: UUID, digest: str) -> dict[str, Any]:
        """Legacy execution entry point; host jobs now require approval in the web UI.

        Approval occurs in the web UI in every mode, not via this tool. Inspect execution and
        verifier exit codes, stdout/stderr, and checks. Report failures and uncertainty;
        do not retry mutations blindly or claim success based only on process exit.
        """
        body = ReviewedJob(digest=digest)
        return await bridge.call(f'/jobs/{job_id}/run', body.model_dump())
