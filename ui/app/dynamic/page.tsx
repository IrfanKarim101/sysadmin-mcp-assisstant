'use client';

import { useEffect, useState } from 'react';
import { AppNav } from '@/components/app-nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { apiFetch } from '@/lib/api';
import { MCPExecutionConnection } from '@/components/mcp-execution-connection';

type Host = { name: string; environment: string };
type Output = { exit_status: number; stdout: string; stderr: string; truncated: boolean };
type Job = { host: string; title: string; scripts: { script: string; verification: string; timeout_seconds: number }; id: string; digest: string; state: string; expires: string;
  result: { execution?: Output; verification?: Output; message?: string } };
const initialScript = 'from pathlib import Path\nPath("/work/result.txt").write_text("hello from the sandbox")\nprint("Created result.txt")\n';
const initialVerifier = 'import json\nfrom pathlib import Path\nprint(json.dumps({"checks": [{"name": "Expected file content", "passed": Path("/work/result.txt").read_text() == "hello from the sandbox"}]}))\n';

export default function DynamicPage() { return <ScriptPage />; }

export function ScriptPage({ hostExecution = false }: { hostExecution?: boolean }) {
  const base = hostExecution ? "/api/scripts" : "/api/dynamic";
  const [hosts, setHosts] = useState<Host[]>([]), [host, setHost] = useState('');
  const [task, setTask] = useState(''), [provider, setProvider] = useState('openai');
  const [script, setScript] = useState(hostExecution ? "" : initialScript), [verification, setVerification] = useState(hostExecution ? "" : initialVerifier);
  const [seconds, setSeconds] = useState(30), [password, setPassword] = useState('');
  const [job, setJob] = useState<Job | null>(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const jobId = job?.id, jobState = job?.state;
  useEffect(() => {
    if (!jobId || jobState !== 'running') return;
    let active = true;
    const id = jobId;
    const timer = setInterval(() => {
      void apiFetch(`${base}/jobs/${id}`).then(async (response) => {
        if (response.ok && active) {
          const updated = await response.json() as Job;
          if (active) setJob(updated);
        }
      }).catch(() => undefined);
    }, 1000);
    return () => { active = false; clearInterval(timer); };
  }, [jobId, jobState, base]);
  useEffect(() => {
    let active = true;
    void (async () => {
      const me = await apiFetch('/api/auth/me');
      if (!me.ok) throw new Error('Sign in to continue.');
      const identity = await me.json() as { csrf_token: string };
      sessionStorage.setItem('sentinel-csrf', identity.csrf_token);
      const response = await apiFetch('/api/hosts');
      if (!response.ok) throw new Error('Could not load VMs.');
      const rows = (await response.json() as Host[]).filter((row) => ['development', 'disposable_lab'].includes(row.environment));
      if (active) { setHosts(rows); setHost(rows[0]?.name ?? ''); }
      const jobId = new URLSearchParams(window.location.search).get('job');
      if (hostExecution && jobId) {
        const saved = await apiFetch(`${base}/jobs/${encodeURIComponent(jobId)}`);
        if (!saved.ok) throw new Error('Job is unavailable in this authenticated session.');
        const loaded = await saved.json() as Job;
        if (active) { setJob(loaded); setHost(loaded.host); setTask(loaded.title); setScript(loaded.scripts.script); setVerification(loaded.scripts.verification); setSeconds(loaded.scripts.timeout_seconds); }
      }
    })().catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load page.'); });
    return () => { active = false; };
  }, [base, hostExecution]);
  async function post(path: string, body: object) {
    const response = await apiFetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json();
    const detail = (data as { detail?: unknown } | null)?.detail;
    if (!response.ok) throw new Error(typeof detail === 'string' ? detail : 'Request denied; check script syntax and selected mode.');
    return data;
  }
  async function act(kind: 'generate' | 'prepare' | 'run') {
    setBusy(true); setError('');
    try {
      if (kind === 'generate') {
        setJob(null);
        const data = await post(`${base}/generate`, { host, task, provider }) as { script: string; verification: string };
        setScript(data.script); setVerification(data.verification);
      } else if (kind === 'prepare') {
        setJob(await post(`${base}/jobs`, { host, title: task.trim().slice(0, 120) || 'Reviewed sandbox script', script, verification, timeout_seconds: seconds }) as Job);
      } else if (job) {
        const current = job;
        setJob({ ...current, state: 'running' });
        setJob(await post(`${base}/jobs/${current.id}/run`, { digest: current.digest, password }) as Job);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Request failed.');
      if (kind === 'run' && job) {
        try {
          const response = await apiFetch(`${base}/jobs/${job.id}`);
          if (response.ok) setJob(await response.json() as Job);
        } catch { /* Keep polling an uncertain in-flight job. */ }
      }
    }
    finally { setBusy(false); setPassword(''); }
  }
  return <main className="min-h-screen text-foreground">
    <header className="flex min-h-20 items-center justify-between border-b px-6 pl-16 md:pl-6"><div><h1 className="font-semibold">{hostExecution ? "Host scripts" : "Dynamic scripts"}</h1><p className="text-xs text-muted-foreground">Generate · Review · Run · Verify</p></div><AppNav /></header>
    <div className="mx-auto max-w-6xl space-y-5 p-6 pb-32">
      <div className="glass-panel rounded-2xl border p-5 text-sm"><p className="font-semibold text-emerald-200">{hostExecution ? "Guided and Autonomous Lab · real host execution" : "Isolated Python execution on a lab VM"}</p><p className="mt-2 text-muted-foreground">{hostExecution ? "Arm Guided or Autonomous Lab with Host scripts. These scripts run on the selected VM as its SSH account; sudo requires separately provisioned noninteractive permission. Every host job requires your approval here, including jobs prepared in Autonomous Lab mode. After approval, installation and verification run automatically. The host helper must be installed. No automatic rollback; changes can persist after failure or stop." : "Arm Dynamic sandbox using the Mode control first. Scripts run in a rootless container: no network, no host mounts, no sudo, and only an ephemeral /work directory. This cannot install software or modify services on the VM. The VM must have the sandbox helper and approved image installed."}</p></div>
      {error && <p role="alert" className="text-sm text-red-200">{error}</p>}
      {hostExecution && <MCPExecutionConnection />}
      <fieldset disabled={busy} className="glass-panel grid gap-4 rounded-2xl border p-5 sm:grid-cols-3">
        <Label className="grid gap-2">VM<NativeSelect value={host} onChange={(event) => { setHost(event.target.value); setJob(null); }}>
          {!hosts.length && <NativeSelectOption value="">No eligible lab VM</NativeSelectOption>}{hosts.map((row) => <NativeSelectOption key={row.name} value={row.name}>{row.name}</NativeSelectOption>)}
        </NativeSelect></Label>
        <Label className="grid gap-2">Generator<NativeSelect value={provider} onChange={(event) => setProvider(event.target.value)}><NativeSelectOption value="openai">ChatGPT</NativeSelectOption><NativeSelectOption value="gemini">Gemini</NativeSelectOption><NativeSelectOption value="local">Local LLM</NativeSelectOption></NativeSelect></Label>
        <Label className="grid gap-2">Total time limit (seconds)<Input type="number" min={1} max={hostExecution ? 900 : 120} value={seconds} onChange={(event) => { setSeconds(Number(event.target.value)); setJob(null); }} /></Label>
        <Label className="grid gap-2 sm:col-span-3">Task<Textarea value={task} maxLength={4000} onChange={(event) => setTask(event.target.value)} placeholder={hostExecution ? "Describe a task for the selected lab VM" : "Describe a task using Python standard-library tools and /work files"} /></Label>
        <Button disabled={!host || !task.trim()} onClick={() => void act('generate')}>Generate draft</Button>
      </fieldset>
      <div className="grid gap-4 lg:grid-cols-2">
        <Label className="grid gap-2">Python script<Textarea aria-label="Python script" disabled={busy} value={script} maxLength={16000} onChange={(event) => { setScript(event.target.value); setJob(null); }} className="min-h-72 font-mono text-xs" /></Label>
        <Label className="grid gap-2">Independent verifier<Textarea aria-label="Independent verifier" disabled={busy} value={verification} maxLength={16000} onChange={(event) => { setVerification(event.target.value); setJob(null); }} className="min-h-72 font-mono text-xs" /></Label>
      </div>
      <p className="text-xs text-muted-foreground">The verifier runs separately against task outputs and must print JSON checks with name and passed fields. Review whether its assertions actually establish your intended result. Syntax checks alone do not make code safe.</p>
      <Button disabled={busy || !host || !script || !verification} onClick={() => void act('prepare')}>Validate and prepare review</Button>
      {job && <section className="glass-panel space-y-4 rounded-2xl border p-5"><h2 className="font-semibold">{job.title} · {job.host} · Job: {job.state.replaceAll('_', ' ')}</h2><p className="break-all font-mono text-xs text-muted-foreground">Reviewed script digest: {job.digest}</p>
        {job.state === 'prepared' && <div className="flex flex-wrap items-end gap-3"><Label className="grid gap-2">Administrator password<Input type="password" autoComplete="current-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} /></Label><Button disabled={busy || !password} onClick={() => void act('run')}>Approve and run once</Button></div>}
        {job.result.message && <p className="text-amber-200">{job.result.message}</p>}
        {(['execution', 'verification'] as const).map((stage) => { const output = job.result[stage]; return output && <div key={stage}><h3 className="text-sm font-medium">{stage} · exit {output.exit_status}{output.truncated ? ' · output limit reached' : ''}</h3><pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded-xl bg-black/40 p-4 text-xs">{output.stdout || '(no stdout)'}{output.stderr && `\nSTDERR:\n${output.stderr}`}</pre></div>; })}
      </section>}
      {busy && <output className="block text-sm text-emerald-200">Working… execution may take up to the selected time limit plus connection and cleanup time.</output>}
    </div>
  </main>;
}
