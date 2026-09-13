'use client';

import { useEffect, useState } from 'react';
import { Check, ChevronDown, Circle, GitPullRequestDraft, LoaderCircle, RotateCcw, ShieldAlert } from 'lucide-react';
import { AppNav } from '@/components/app-nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { apiFetch } from '@/lib/api';

type Action = { action: string; host: string; target: string; value?: string; version?: string };
type Change = {
  id: string; title: string; state: string; actions: Action[]; plan_hash: string; created_at: string; updated_at: string;
  diff_hash?: string; preview?: { effect: string; service_impact?: string; validation?: string; rollback_strategy?: string; recovery_snapshot?: { reference: string; checksum: string; expires_at: string; verified: boolean }; managed_file?: { resolved_path: string; validator: string; owner: string; group: string; mode: string; diff: string; diff_truncated: boolean; atomic_steps: string[] }; package?: { package_name: string; requested_version: string; dependencies: string[]; removals: string[]; download_bytes: number; disk_bytes: number; reboot_required: boolean; dependent_services: string[]; repository_change: boolean; key_change: boolean; rollback_limitation: string }; service?: { unit: string; impact: string; configuration_validated: boolean; material_approval_required: boolean; verification_checks: { type: string }[]; verification_rule: string; clear_failure_action: string } }[];
  evidence: { stage: string; status: string; remote_mutation: boolean; snapshots?: { reference: string; snapshot_type: string; checksum: string; expires_at: string; verified: boolean }[]; post_rollback_check?: string; [key: string]: unknown }[];
  approval_token?: string;
  approval_expires_at?: string | null; rollback_available: boolean;
};
type Host = { name: string };
type FilePolicySet = { host: string; files: { id: string; path: string; validator: string; mode: string; max_bytes: number }[] };
type PackagePolicySet = { host: string; manager: string; packages: { id: string; name: string; allowed_versions: string[]; held: boolean }[] };
type ServicePolicySet = { host: string; services: { id: string; unit: string; actions: string[]; material_restart: boolean }[] };

const actionTypes = [
  'write_managed_file', 'install_package', 'update_package', 'enable_service',
  'disable_service', 'reload_service', 'restart_service', 'run_backup',
];
const workflow = ['Inspect', 'Plan', 'Preview', 'Backup', 'Apply', 'Validate', 'Activate', 'Verify', 'Rollback'];

function completedSteps(item: Change) {
  const done = new Set<string>(['Inspect', 'Plan']);
  if (item.preview) done.add('Preview');
  for (const entry of item.evidence) {
    const label = ({ backup: 'Backup', apply: 'Apply', validate: 'Validate', activate: 'Activate', verify: 'Verify', rollback: 'Rollback' } as Record<string, string>)[entry.stage];
    if (label) done.add(label);
  }
  if (item.evidence.some((entry) => entry.stage === 'validate') && item.actions.some((entry) => entry.action.endsWith('_service'))) done.add('Activate');
  return done;
}

function WorkflowProgress({ item }: { item: Change }) {
  const done = completedSteps(item);
  return <div className="mt-4 grid grid-cols-3 gap-2 sm:grid-cols-5 xl:grid-cols-9" aria-label="Change workflow progress">{workflow.map((step) => {
    const complete = done.has(step);
    const optionalRollback = step === 'Rollback' && !complete;
    return <div key={step} className={`rounded-lg border p-2 text-center text-[10px] ${complete ? 'border-emerald-400/25 bg-emerald-400/5 text-emerald-200' : optionalRollback && item.rollback_available ? 'border-amber-400/25 text-amber-200' : 'text-muted-foreground'}`}>
      {complete ? <Check className="mx-auto mb-1 size-3"/> : <Circle className="mx-auto mb-1 size-3"/>}{step}
    </div>;
  })}</div>;
}

export default function ChangesPage() {
  const [hosts, setHosts] = useState<Host[]>([]), [items, setItems] = useState<Change[]>([]);
  const [filePolicies, setFilePolicies] = useState<FilePolicySet[]>([]);
  const [packagePolicies, setPackagePolicies] = useState<PackagePolicySet[]>([]);
  const [servicePolicies, setServicePolicies] = useState<ServicePolicySet[]>([]);
  const [title, setTitle] = useState(''), [host, setHost] = useState('');
  const [action, setAction] = useState(actionTypes[0]), [target, setTarget] = useState('');
  const [value, setValue] = useState(''), [password, setPassword] = useState('');
  const [version, setVersion] = useState('');
  const [activationPassword, setActivationPassword] = useState('');
  const [tokens, setTokens] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false), [error, setError] = useState('');

  async function load() {
    const [hostResponse, changeResponse, policyResponse, packageResponse, serviceResponse] = await Promise.all([apiFetch('/api/hosts'), apiFetch('/api/changes'), apiFetch('/api/managed-files/policies'), apiFetch('/api/packages/policies'), apiFetch('/api/services/policies')]);
    if (!hostResponse.ok || !changeResponse.ok || !policyResponse.ok || !packageResponse.ok || !serviceResponse.ok) throw new Error('Could not load change workspace.');
    const hostData = (await hostResponse.json()) as Host[];
    setHosts(hostData); setHost((current) => current || hostData[0]?.name || '');
    setItems((await changeResponse.json()) as Change[]);
    setFilePolicies((await policyResponse.json()) as FilePolicySet[]);
    setPackagePolicies((await packageResponse.json()) as PackagePolicySet[]);
    setServicePolicies((await serviceResponse.json()) as ServicePolicySet[]);
  }
  useEffect(() => {
    void load().catch((reason) => setError(reason instanceof Error ? reason.message : 'API unavailable.'));
    const timer = setInterval(() => void load().catch(() => undefined), 5_000);
    return () => clearInterval(timer);
  }, []);

  async function call(path: string, body?: object) {
    setBusy(true); setError('');
    try {
      const response = await apiFetch(path, { method: 'POST', headers: body ? { 'content-type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
      const data = (await response.json()) as Change & { detail?: string };
      if (!response.ok) throw new Error(data.detail || 'Request denied.');
      if (data.approval_token) setTokens((old) => ({ ...old, [data.id]: data.approval_token! }));
      setItems((old) => [data, ...old.filter((item) => item.id !== data.id)]);
      return data;
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Request failed.'); }
    finally { setBusy(false); }
  }
  async function create(event: React.FormEvent) {
    event.preventDefault();
    const data = await call('/api/changes', { title, actions: [{ action, host, target, ...(action === 'write_managed_file' ? { value } : {}), ...(['install_package','update_package'].includes(action) && version ? { version } : {}) }] });
    if (data) { setTitle(''); setTarget(''); setValue(''); setVersion(''); }
  }
  const availableFiles = filePolicies.find((item) => item.host === host)?.files || [];
  const availablePackages = packagePolicies.find((item) => item.host === host)?.packages || [];
  const selectedPackage = availablePackages.find((item) => item.id === target);
  const packageAction = ['install_package','update_package'].includes(action);
  const serviceAction = ['enable_service','disable_service','reload_service','restart_service'].includes(action);
  const availableServices = (servicePolicies.find((item) => item.host === host)?.services || []).filter((item) => item.actions.includes(action));

  return <main className="min-h-screen bg-background text-foreground">
    <header className="flex min-h-16 items-center border-b px-6 py-3"><div><h1 className="font-semibold">Change transactions</h1><p className="text-xs text-muted-foreground">Human-approved automation workflow</p></div><AppNav /></header>
    <section className="mx-auto max-w-6xl space-y-5 p-6">
      <div className="flex gap-3 rounded-2xl border border-amber-400/25 bg-amber-400/5 p-4"><ShieldAlert className="size-5 text-amber-300"/><div><p className="font-medium text-amber-100">Simulation only — no remote mutation</p><p className="text-xs text-muted-foreground">Plans are typed, scope-checked, hashed, reauthenticated, single-use, and recorded. Phase 16 does not write files, install packages, or restart services.</p></div></div>
      {error && <p role="alert" className="rounded-xl bg-red-400/10 p-3 text-sm text-red-200">{error}</p>}
      <div className="grid gap-5 lg:grid-cols-[360px_1fr]">
        <form onSubmit={create} className="space-y-3 rounded-2xl border bg-card p-5">
          <h2 className="flex items-center gap-2 font-medium"><GitPullRequestDraft className="size-4"/>New typed plan</h2>
          <Label>Title<Input required maxLength={120} value={title} onChange={(e) => setTitle(e.target.value)}/></Label>
          <Label>Host<NativeSelect value={host} onChange={(e) => { setHost(e.target.value); setTarget(''); }}>{hosts.map((item) => <NativeSelectOption key={item.name} value={item.name}>{item.name}</NativeSelectOption>)}</NativeSelect></Label>
          <Label>Action<NativeSelect value={action} onChange={(e) => { setAction(e.target.value); setTarget(''); }}>{actionTypes.map((item) => <NativeSelectOption key={item} value={item}>{item.replaceAll('_', ' ')}</NativeSelectOption>)}</NativeSelect></Label>
          {action === 'write_managed_file' ? <Label>Managed path ID<NativeSelect required value={target} onChange={(e) => setTarget(e.target.value)}><NativeSelectOption value="">Select an allowlisted file</NativeSelectOption>{availableFiles.map((item) => <NativeSelectOption key={item.id} value={item.id}>{item.id} — {item.path}</NativeSelectOption>)}</NativeSelect><span className="text-[11px] text-muted-foreground">The API receives this ID, never a raw path.</span></Label> : packageAction ? <><Label>Package ID<NativeSelect required value={target} onChange={(e) => { setTarget(e.target.value); setVersion(''); }}><NativeSelectOption value="">Select an allowlisted package</NativeSelectOption>{availablePackages.map((item) => <NativeSelectOption key={item.id} value={item.id}>{item.id} — {item.name}{item.held ? ' (held)' : ''}</NativeSelectOption>)}</NativeSelect></Label>{selectedPackage && <Label>Approved version<NativeSelect value={version} onChange={(e) => setVersion(e.target.value)}><NativeSelectOption value="">Policy default</NativeSelectOption>{selectedPackage.allowed_versions.map((item) => <NativeSelectOption key={item} value={item}>{item}</NativeSelectOption>)}</NativeSelect></Label>}</> : serviceAction ? <Label>Service ID<NativeSelect required value={target} onChange={(e) => setTarget(e.target.value)}><NativeSelectOption value="">Select an allowlisted service</NativeSelectOption>{availableServices.map((item) => <NativeSelectOption key={item.id} value={item.id}>{item.id} — {item.unit}</NativeSelectOption>)}</NativeSelect></Label> : <Label>Policy target<Input required maxLength={128} value={target} onChange={(e) => setTarget(e.target.value)}/></Label>}
          {action === 'write_managed_file' && <Label>Proposed content<textarea required maxLength={32000} className="mt-1 min-h-28 w-full rounded-md border bg-background p-2 text-sm" value={value} onChange={(e) => setValue(e.target.value)}/></Label>}
          <Button className="w-full" disabled={busy || !host}>{busy && <LoaderCircle className="animate-spin"/>}Create plan</Button>
        </form>
        <div className="space-y-4">{items.length === 0 && <div className="rounded-2xl border border-dashed p-10 text-center text-sm text-muted-foreground">No transactions in this session.</div>}{items.map((item) => <article key={item.id} className="rounded-2xl border bg-card p-5">
          <div className="flex flex-wrap justify-between gap-2"><h2 className="font-medium">{item.title}</h2><span className="rounded-full bg-muted px-3 py-1 text-xs">{item.state}</span></div>
          <WorkflowProgress item={item}/>
          <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-muted-foreground">
            {[...new Set(item.actions.map((entry) => entry.host))].map((name) => <span key={name} className="rounded-full border px-2 py-1">{name} · {item.state}</span>)}
            <span>Updated {new Date(item.updated_at).toLocaleString()}</span>
            {item.approval_expires_at && <span className="text-amber-200">Approval expires {new Date(item.approval_expires_at).toLocaleString()}</span>}
            {item.rollback_available && <span className="flex items-center gap-1 text-emerald-200"><RotateCcw className="size-3"/>Rollback available</span>}
          </div>
          <p className="mt-2 break-all font-mono text-[10px] text-muted-foreground">plan {item.plan_hash}</p>{item.diff_hash && <p className="break-all font-mono text-[10px] text-muted-foreground">diff {item.diff_hash}</p>}
          <ul className="mt-3 space-y-2 text-sm">{(item.preview || item.actions.map((x) => ({ effect: `${x.action.replaceAll('_', ' ')} ${x.target} on ${x.host}` }))).map((x, index) => <li key={index}><p>{x.effect}</p>{x.service_impact && <p className="text-xs text-muted-foreground">Impact: {x.service_impact} · Validate: {x.validation} · Rollback: {x.rollback_strategy}</p>}{x.recovery_snapshot && <p className="mt-1 break-all font-mono text-[10px] text-emerald-200">Pre-approval backup verified: {x.recovery_snapshot.reference} · {x.recovery_snapshot.checksum}</p>}{x.managed_file && <div className="mt-2 rounded-lg border p-3"><p className="text-xs">{x.managed_file.resolved_path} · {x.managed_file.owner}:{x.managed_file.group} · {x.managed_file.mode} · validator {x.managed_file.validator}</p><pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded bg-background p-3 text-[11px]">{x.managed_file.diff}</pre>{x.managed_file.diff_truncated && <p className="mt-1 text-xs text-amber-200">Diff was bounded; approval is disabled until policy permits a complete preview.</p>}</div>}{x.package && <div className="mt-2 rounded-lg border p-3 text-xs"><p>{x.package.package_name} → {x.package.requested_version} · download {x.package.download_bytes.toLocaleString()} B · disk {x.package.disk_bytes.toLocaleString()} B</p><p className="text-muted-foreground">Dependencies: {x.package.dependencies.join(', ') || 'none'} · Removals: {x.package.removals.join(', ') || 'none'} · Reboot: {x.package.reboot_required ? 'required' : 'no'}</p><p className="text-muted-foreground">Repositories/keys unchanged · Verify services: {x.package.dependent_services.join(', ') || 'none'}</p><p className="text-amber-200">Rollback: {x.package.rollback_limitation}</p></div>}</li>)}</ul>
          {item.preview?.flatMap((x) => x.service ? [x.service] : []).map((service) => <div key={service.unit} className="mt-3 rounded-lg border p-3 text-xs"><p>{service.unit} · {service.impact}</p><p className="text-muted-foreground">Configuration validated: {service.configuration_validated ? 'yes' : 'no'} · Checks: {service.verification_checks.map((x) => x.type).join(', ')}</p><p className="text-amber-200">{service.verification_rule} · Failure: {service.clear_failure_action}</p></div>)}
          {item.evidence.length > 0 && <div className="mt-3 space-y-2 text-xs text-emerald-200"><p>{item.evidence.map((x) => `${x.stage}: ${x.status} (remote mutation: no)`).join(' · ')}</p>{item.evidence.flatMap((x) => x.snapshots || []).map((snapshot) => <div key={snapshot.reference} className="rounded-lg border border-emerald-400/15 p-2"><p>{snapshot.snapshot_type} · verified · expires {new Date(snapshot.expires_at).toLocaleString()}</p><p className="break-all font-mono text-[10px] text-muted-foreground">{snapshot.reference} · sha256 {snapshot.checksum}</p></div>)}</div>}
          {item.evidence.length > 0 && <details className="mt-3 rounded-lg border"><summary className="flex cursor-pointer list-none items-center gap-2 p-3 text-xs font-medium"><ChevronDown className="size-3"/>Raw evidence ({item.evidence.length} events)</summary><pre className="max-h-96 overflow-auto whitespace-pre-wrap border-t bg-background p-3 text-[10px] text-foreground">{JSON.stringify(item.evidence, null, 2)}</pre></details>}
          <div className="mt-4 flex flex-wrap gap-2">
            {item.state === 'planned' && <Button disabled={busy} onClick={() => call(`/api/changes/${item.id}/preview`)}>Preview</Button>}
            {item.state === 'previewed' && <><Input className="max-w-56" type="password" placeholder="Re-enter password" value={password} onChange={(e) => setPassword(e.target.value)}/><Button disabled={busy || !password} onClick={async () => { await call(`/api/changes/${item.id}/approve`, { password }); setPassword(''); }}>Approve</Button></>}
            {item.state === 'approved' && <>{item.preview?.some((x) => x.service?.material_approval_required) && <Input className="max-w-56" type="password" placeholder="Confirm material activation" value={activationPassword} onChange={(e) => setActivationPassword(e.target.value)}/>}<Button disabled={busy || !tokens[item.id] || (!!item.preview?.some((x) => x.service?.material_approval_required) && !activationPassword)} onClick={async () => { await call(`/api/changes/${item.id}/simulate`, { approval_token: tokens[item.id], ...(activationPassword ? { activation_password: activationPassword } : {}) }); setActivationPassword(''); }}>Run simulation</Button></>}
            {item.state === 'verifying' && <><Button disabled={busy} onClick={() => call(`/api/changes/${item.id}/accept`)}>Accept evidence</Button><Button variant="outline" disabled={busy} onClick={() => call(`/api/changes/${item.id}/rollback`)}>Simulate rollback</Button></>}
            {['planned','previewed','approved'].includes(item.state) && <Button variant="outline" disabled={busy} onClick={() => call(`/api/changes/${item.id}/cancel`)}>Cancel</Button>}
          </div>
        </article>)}</div>
      </div>
    </section>
  </main>;
}
