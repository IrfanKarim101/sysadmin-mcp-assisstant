'use client';

import { useEffect, useState } from 'react';
import { Package, ShieldCheck, LoaderCircle } from 'lucide-react';
import { AppNav } from '@/components/app-nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { apiFetch } from '@/lib/api';

type Profile = { id: string; label: string; upgrade_notes: string; delivery: string };
type Host = { name: string; environment: string };
type Plan = { host: string; product: string; operation: string; deployment: string;
  target_version: string; steps: string[]; status: string; blocking_requirements: string[] };

export default function SoftwarePage() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [host, setHost] = useState('');
  const [product, setProduct] = useState('nginx');
  const [deployment, setDeployment] = useState('native');
  const [operation, setOperation] = useState('install');
  const [version, setVersion] = useState('');
  const [plan, setPlan] = useState<Plan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    void (async () => {
      const identity = await apiFetch('/api/auth/me');
      if (!identity.ok) throw new Error('Sign in to view software workflows.');
      const auth = await identity.json() as { csrf_token: string };
      sessionStorage.setItem('sentinel-csrf', auth.csrf_token);
      const [catalog, fleet] = await Promise.all([apiFetch('/api/software'), apiFetch('/api/hosts')]);
      if (!catalog.ok || !fleet.ok) throw new Error('Administrator access is required to load software workflows.');
      const choices = await catalog.json() as Profile[];
      const machines = (await fleet.json() as Host[]).filter((row) => ['development', 'disposable_lab'].includes(row.environment));
      if (active) { setProfiles(choices); setHosts(machines); setHost(machines[0]?.name ?? ''); }
    })().catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load workflows.'); });
    return () => { active = false; };
  }, []);
  async function preview(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(''); setPlan(null);
    try {
      const response = await apiFetch('/api/software/plan', { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ host, product, operation, deployment, target_version: version }) });
      const result = await response.json() as Plan & { detail?: string };
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Check the VM and exact target version.');
      setPlan(result);
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not prepare workflow.'); }
    finally { setBusy(false); }
  }
  return <main className="min-h-screen text-foreground">
    <header className="flex min-h-20 items-center justify-between border-b px-6 pl-16 md:pl-6">
      <div><h1 className="flex items-center gap-2 font-semibold"><Package className="size-5 text-emerald-300" />Software management</h1><p className="mt-1 text-xs text-muted-foreground">Rocky Linux 9 · Native services and Podman</p></div><AppNav />
    </header>
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <div className="glass-panel rounded-2xl border p-5"><h2 className="flex items-center gap-2 font-medium"><ShieldCheck className="size-4 text-emerald-300" />Data stays with the application</h2><p className="mt-2 text-sm text-muted-foreground">Upgrades require a consistent backup, compatibility checks, and verification of existing data. Cross-release migrations and native-to-container conversions are separate operations.</p></div>
      <p className="rounded-xl border border-amber-300/20 bg-amber-300/5 p-4 text-sm text-amber-200">Planning available. Live execution is not enabled: a Rocky 9 VM, host adapters, and installation/restore acceptance tests are still required.</p>
      {error && <p role="alert" className="text-sm text-red-200">{error}</p>}
      <form onSubmit={(event) => void preview(event)} className="glass-panel grid gap-5 rounded-2xl border p-5 sm:grid-cols-2">
        <Label className="grid gap-2">VM<NativeSelect value={host} disabled={busy} onChange={(event) => { setHost(event.target.value); setPlan(null); }}>
          {!hosts.length && <NativeSelectOption value="">Add a development or disposable-lab VM</NativeSelectOption>}{hosts.map((row) => <NativeSelectOption key={row.name} value={row.name}>{row.name}</NativeSelectOption>)}
        </NativeSelect></Label>
        <Label className="grid gap-2">Software<NativeSelect value={product} disabled={busy} onChange={(event) => { setProduct(event.target.value); setVersion(''); setPlan(null); }}>{profiles.map((row) => <NativeSelectOption key={row.id} value={row.id}>{row.label}</NativeSelectOption>)}</NativeSelect></Label>
        <Label className="grid gap-2">Deployment<NativeSelect value={deployment} disabled={busy} onChange={(event) => { setDeployment(event.target.value); setPlan(null); }}><NativeSelectOption value="native">Native systemd service</NativeSelectOption><NativeSelectOption value="podman">Podman container</NativeSelectOption></NativeSelect></Label>
        <Label className="grid gap-2">Operation<NativeSelect value={operation} disabled={busy} onChange={(event) => { setOperation(event.target.value); setPlan(null); }}><NativeSelectOption value="install">Fresh install</NativeSelectOption><NativeSelectOption value="upgrade">Upgrade and preserve data</NativeSelectOption></NativeSelect></Label>
        <Label className="grid gap-2">Exact target version<Input value={version} disabled={busy} placeholder="major.minor.patch" pattern="[0-9]+\.[0-9]+\.[0-9]+" required onChange={(event) => { setVersion(event.target.value); setPlan(null); }} /></Label>
        <div className="flex items-end"><Button disabled={busy || !host || !version || !profiles.length} type="submit">{busy && <LoaderCircle className="animate-spin" />}Preview workflow</Button></div>
        <p className="text-sm text-muted-foreground sm:col-span-2">{profiles.find((row) => row.id === product)?.upgrade_notes}</p>
      </form>
      {plan && <section className="glass-panel rounded-2xl border p-5"><h2 className="font-medium">{plan.product} {plan.operation} · {plan.host} · {plan.target_version}</h2><p className="mt-2 text-xs text-amber-200">Proposed steps only; no host inspection or installation has run.</p><ol className="mt-4 list-decimal space-y-2 pl-5 text-sm text-muted-foreground">{plan.steps.map((step) => <li key={step}>{step.replaceAll('_', ' ')}</li>)}</ol></section>}
    </div>
  </main>;
}
