'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { AlertTriangle, LoaderCircle, Pause, Play, Shield, ShieldAlert, Square } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch } from '@/lib/api';

type Mode = 'observe' | 'guided' | 'autonomous_lab';
type Authority = {
  mode: Mode; status: 'inactive' | 'active' | 'paused'; owner: string | null;
  hosts: string[]; capabilities: string[]; action_budget: number;
  concurrency: number; expires_at: string | null; available_capabilities?: string[];
};
type Host = { name: string; hostname: string; environment: string };
const labels: Record<string, string> = {
  observe: 'Observe', guided: 'Guided', autonomous_lab: 'Autonomous Lab',
  managed_files: 'Managed files', packages: 'Packages', services: 'Services',
  backups: 'Backups',
};

export function AuthorityControl() {
  const [state, setState] = useState<Authority | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [clock, setClock] = useState(Date.now());
  const [form, setForm] = useState({
    mode: 'guided' as Exclude<Mode, 'observe'>, hosts: [] as string[],
    capabilities: ['services'] as string[], duration_minutes: 15,
    action_budget: 5, concurrency: 1, password: '',
  });

  const refresh = useCallback(async () => {
    const [modeResponse, hostResponse] = await Promise.all([
      apiFetch('/api/authority'), apiFetch('/api/hosts'),
    ]);
    if (!modeResponse.ok || !hostResponse.ok) return;
    setState(await modeResponse.json() as Authority);
    setHosts(await hostResponse.json() as Host[]);
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const timer = setInterval(() => {
      setClock(Date.now());
      if (state?.mode !== 'observe') void refresh();
    }, 10_000);
    return () => clearInterval(timer);
  }, [refresh, state?.mode]);

  async function arm(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await apiFetch('/api/authority/arm', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await response.json() as Authority & { detail?: string };
      if (!response.ok) throw new Error(data.detail ?? 'Could not arm authority mode.');
      setState(data); setOpen(false); setForm((current) => ({ ...current, password: '' }));
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not arm authority mode.'); }
    finally { setBusy(false); }
  }

  async function transition(action: 'pause' | 'resume' | 'stop' | 'emergency-stop') {
    if (action === 'emergency-stop' && !confirm('Emergency-stop all supervised automation now?')) return;
    setBusy(true); setError('');
    try {
      const response = await apiFetch(`/api/authority/${action}`, { method: 'POST' });
      const data = await response.json() as Authority & { detail?: string };
      if (!response.ok) throw new Error(data.detail ?? `Could not ${action} authority mode.`);
      setState(data);
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Authority transition failed.'); }
    finally { setBusy(false); }
  }

  if (!state) return null;
  const remaining = state.expires_at
    ? Math.max(0, Math.ceil((new Date(state.expires_at).getTime() - clock) / 60_000)) : 0;
  const selectableHosts = form.mode === 'autonomous_lab'
    ? hosts.filter((host) => ['development', 'disposable_lab'].includes(host.environment)) : hosts;

  return <>
    {state.mode === 'observe' ? <Button type="button" onClick={() => setOpen(true)} className="fixed bottom-4 right-4 z-[70] border border-emerald-400/30 bg-card text-emerald-200 shadow-xl hover:bg-accent">
      <Shield />Mode: Observe
    </Button> : <aside className="fixed inset-x-4 bottom-4 z-[70] mx-auto flex max-w-4xl flex-wrap items-center gap-3 rounded-2xl border border-amber-400/30 bg-zinc-950/95 p-3 shadow-2xl backdrop-blur">
      <ShieldAlert className="text-amber-300" />
      <div className="min-w-40 flex-1"><p className="text-sm font-semibold text-amber-100">{labels[state.mode]} · {state.status}</p><p className="text-xs text-muted-foreground">{state.hosts.length} host(s) · {remaining} min remaining · no write actions implemented yet</p></div>
      {state.status === 'active' ? <Button size="sm" variant="outline" disabled={busy} onClick={() => void transition('pause')}><Pause />Pause</Button> : <Button size="sm" variant="outline" disabled={busy} onClick={() => void transition('resume')}><Play />Resume</Button>}
      <Button size="sm" variant="outline" disabled={busy} onClick={() => void transition('stop')}><Square />Disable</Button>
      <Button size="sm" variant="destructive" disabled={busy} onClick={() => void transition('emergency-stop')}><AlertTriangle />Emergency stop</Button>
    </aside>}

    {open && <div className="fixed inset-0 z-[80] grid place-items-center overflow-y-auto bg-black/70 p-4" role="dialog" aria-modal="true" aria-labelledby="authority-title">
      <form onSubmit={arm} className="my-8 w-full max-w-xl rounded-2xl border bg-card p-6 shadow-2xl">
        <div className="flex items-start gap-3"><ShieldAlert className="mt-1 text-amber-300" /><div><h2 id="authority-title" className="text-lg font-semibold">Arm supervised authority</h2><p className="text-sm text-muted-foreground">This creates temporary server-side authority only. Phase 15 exposes no new write actions.</p></div></div>
        {error && <p role="alert" className="mt-4 rounded-lg bg-red-400/10 p-3 text-sm text-red-200">{error}</p>}
        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <Label className="grid gap-2">Mode<select className="h-9 rounded-lg border bg-background px-3" value={form.mode} onChange={(event) => setForm({ ...form, mode: event.target.value as typeof form.mode, hosts: [] })}><option value="guided">Guided</option><option value="autonomous_lab">Autonomous Lab</option></select></Label>
          <Label className="grid gap-2">Duration<select className="h-9 rounded-lg border bg-background px-3" value={form.duration_minutes} onChange={(event) => setForm({ ...form, duration_minutes: Number(event.target.value) })}><option value={15}>15 minutes</option><option value={30}>30 minutes</option><option value={60}>60 minutes</option></select></Label>
          <Label className="grid gap-2">Action budget<Input type="number" min={1} max={50} value={form.action_budget} onChange={(event) => setForm({ ...form, action_budget: Number(event.target.value) })} /></Label>
          <Label className="grid gap-2">Concurrency<Input type="number" min={1} max={Math.min(3, Math.max(1, form.hosts.length))} value={form.concurrency} onChange={(event) => setForm({ ...form, concurrency: Number(event.target.value) })} /></Label>
        </div>
        <fieldset className="mt-5"><legend className="text-sm font-medium">Target hosts</legend><div className="mt-2 grid gap-2 sm:grid-cols-2">{selectableHosts.map((host) => <label key={host.name} className="flex gap-2 rounded-lg border p-3 text-sm"><input type="checkbox" checked={form.hosts.includes(host.name)} onChange={(event) => setForm({ ...form, hosts: event.target.checked ? [...form.hosts, host.name] : form.hosts.filter((name) => name !== host.name) })} /><span>{host.name}<small className="block text-muted-foreground">{host.environment}</small></span></label>)}</div>{!selectableHosts.length && <p className="mt-2 text-xs text-amber-200">No hosts are eligible. Classify a VM as development or disposable lab first.</p>}</fieldset>
        <fieldset className="mt-5"><legend className="text-sm font-medium">Capability scope</legend><div className="mt-2 flex flex-wrap gap-3">{(state.available_capabilities ?? []).map((capability) => <label key={capability} className="flex gap-2 text-sm"><input type="checkbox" checked={form.capabilities.includes(capability)} onChange={(event) => setForm({ ...form, capabilities: event.target.checked ? [...form.capabilities, capability] : form.capabilities.filter((item) => item !== capability) })} />{labels[capability]}</label>)}</div></fieldset>
        <Label className="mt-5 grid gap-2">Administrator password<Input required type="password" autoComplete="current-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></Label>
        <p className="mt-4 text-xs text-muted-foreground">Observe remains the default after logout, expiry, emergency stop, or backend restart.</p>
        <div className="mt-5 flex justify-end gap-2"><Button type="button" variant="outline" disabled={busy} onClick={() => { setOpen(false); setError(''); }}>Cancel</Button><Button type="submit" disabled={busy || !form.hosts.length || !form.capabilities.length}>{busy && <LoaderCircle className="animate-spin" />}Arm mode</Button></div>
      </form>
    </div>}
  </>;
}
