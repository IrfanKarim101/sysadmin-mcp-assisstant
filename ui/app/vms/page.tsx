'use client';
import { FormEvent, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Fingerprint,
  LoaderCircle,
  MonitorCog,
  Plus,
  Server,
  Trash2,
} from 'lucide-react';
import { AppNav } from '@/components/app-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { apiFetch } from '@/lib/api';

type Host = {
  name: string;
  hostname: string;
  allowed_logs: string[];
  restart_services: string[];
  backup_jobs: string[];
  environment: 'production' | 'staging' | 'development' | 'disposable_lab';
};
type Pending = {
  token: string;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
};
const initial = {
  name: '',
  hostname: '',
  port: '22',
  username: '',
  password: '',
  allowed_logs: '/var/log/syslog\n/var/log/auth.log',
  restart_services: '',
  backup_jobs: 'database-dump',
  environment: 'production',
};

export default function VmsPage() {
  const [hosts, setHosts] = useState<Host[]>([]),
    [form, setForm] = useState(initial),
    [pending, setPending] = useState<Pending | null>(null),
    [busy, setBusy] = useState(false),
    [removing, setRemoving] = useState(''),
    [error, setError] = useState(''),
    [notice, setNotice] = useState('');
  const [classification, setClassification] = useState<{
    host: Host; environment: Host['environment']; password: string;
  } | null>(null);
  async function load() {
    const me = await apiFetch('/api/auth/me');
    if (!me.ok) return;
    const identity = (await me.json()) as { csrf_token: string };
    sessionStorage.setItem('sentinel-csrf', identity.csrf_token);
    const response = await apiFetch('/api/hosts');
    if (!response.ok) throw new Error('Could not load managed VMs.');
    setHosts((await response.json()) as Host[]);
  }
  useEffect(() => {
    void load().catch(() => setError('The local agent API is offline.'));
  }, []);
  function update(key: keyof typeof initial, value: string) {
    setForm((current) => ({ ...current, [key]: value }));
  }
  async function discover(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const response = await apiFetch('/api/hosts/discover-key', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ...form,
          port: Number(form.port),
          allowed_logs: form.allowed_logs
            .split('\n')
            .map((x) => x.trim())
            .filter(Boolean),
          restart_services: form.restart_services
            .split('\n')
            .map((x) => x.trim())
            .filter(Boolean),
          backup_jobs: form.backup_jobs
            .split('\n')
            .map((x) => x.trim())
            .filter(Boolean),
          cpu_threshold: 90,
          memory_threshold: 90,
        }),
      });
      const data = (await response.json()) as Pending & { detail?: string };
      if (!response.ok)
        throw new Error(data.detail ?? 'Could not contact the SSH server.');
      setPending(data);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Connection failed.');
    } finally {
      setBusy(false);
    }
  }
  async function decide(trust: boolean) {
    if (!pending) return;
    setBusy(true);
    setError('');
    try {
      const response = await apiFetch('/api/hosts/decide-key', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: pending.token, trust }),
      });
      const data = (await response.json()) as {
        trusted: boolean;
        host?: Host;
        detail?: string;
      };
      if (!response.ok)
        throw new Error(data.detail ?? 'Host-key decision failed.');
      setPending(null);
      if (data.trusted && data.host) {
        setHosts((current) => [...current, data.host!]);
        setForm(initial);
        setNotice(`${data.host.name} was added to the managed fleet.`);
      }
    } catch (reason) {
      setPending(null);
      setError(
        reason instanceof Error
          ? `${reason.message} Fetch the host key again and verify the new fingerprint before accepting it.`
          : 'Could not save this VM. Fetch the host key again before accepting it.',
      );
    } finally {
      setBusy(false);
    }
  }
  async function remove(host: Host) {
    if (
      !confirm(
        `Remove ${host.name} from Evesdropctl?\n\nThis removes its managed configuration and trusted host-key entry. It does not modify the VM.`,
      )
    )
      return;
    setRemoving(host.name);
    setError('');
    setNotice('');
    try {
      const response = await apiFetch('/api/hosts/remove', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: host.name }),
      });
      const data = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(data.detail ?? 'Could not remove VM.');
      setHosts((current) => current.filter((item) => item.name !== host.name));
      setNotice(
        `${host.name} was removed from Evesdropctl. The VM itself was not changed.`,
      );
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : 'Could not remove VM.',
      );
    } finally {
      setRemoving('');
    }
  }
  async function classify(event: FormEvent) {
    event.preventDefault();
    if (!classification) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const response = await apiFetch('/api/hosts/classify', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: classification.host.name,
          environment: classification.environment,
          password: classification.password,
        }),
      });
      const data = await response.json() as { detail?: string };
      if (!response.ok) throw new Error(data.detail ?? 'Could not classify VM.');
      setHosts((current) => current.map((item) => item.name === classification.host.name
        ? { ...item, environment: classification.environment } : item));
      setNotice(`${classification.host.name} is now classified as ${classification.environment.replace('_', ' ')}.`);
      setClassification(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not classify VM.');
    } finally { setBusy(false); }
  }
  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="flex min-h-16 items-center justify-between border-b px-6 py-3">
        <div>
          <h1 className="font-semibold">VM management</h1>
          <p className="text-xs text-muted-foreground">
            Enroll and remove approved SSH targets
          </p>
        </div>
        <AppNav />
      </header>
      <section className="mx-auto grid max-w-7xl gap-6 p-6 xl:grid-cols-[minmax(0,1fr)_25rem]">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-medium">Managed VMs</h2>
              <p className="text-sm text-muted-foreground">
                {hosts.length} approved{' '}
                {hosts.length === 1 ? 'target' : 'targets'}
              </p>
            </div>
            <Badge variant="outline">Configuration inventory</Badge>
          </div>
          {notice && (
            <p className="rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-200">
              {notice}
            </p>
          )}
          {error && (
            <p
              role="alert"
              className="rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200"
            >
              {error}
            </p>
          )}
          <div className="space-y-3">
            {hosts.map((host) => (
              <article
                key={host.name}
                className="flex flex-wrap items-center gap-4 rounded-2xl border bg-card p-5"
              >
                <div className="grid size-10 place-items-center rounded-xl bg-emerald-400/10 text-emerald-300">
                  <Server className="size-5" />
                </div>
                <div className="min-w-48 flex-1">
                  <h3 className="font-medium">{host.name}</h3>
                  <p className="text-xs text-muted-foreground">
                    {host.hostname} · {host.allowed_logs.length} approved log{' '}
                    {host.allowed_logs.length === 1 ? 'path' : 'paths'} ·{' '}
                    {host.backup_jobs.length} backup{' '}
                    {host.backup_jobs.length === 1 ? 'job' : 'jobs'}
                  </p>
                </div>
                <Button type="button" variant="ghost" size="sm" onClick={() => setClassification({ host, environment: host.environment, password: '' })}>
                  <Badge variant="outline">{host.environment.replace('_', ' ')}</Badge>
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={removing === host.name}
                  onClick={() => void remove(host)}
                  className="text-red-300 hover:text-red-200"
                >
                  {removing === host.name ? (
                    <LoaderCircle className="animate-spin" />
                  ) : (
                    <Trash2 />
                  )}
                  Remove
                </Button>
              </article>
            ))}
            {hosts.length === 0 && (
              <div className="rounded-2xl border border-dashed p-10 text-center">
                <MonitorCog className="mx-auto size-7 text-muted-foreground" />
                <p className="mt-3 text-sm">No managed VMs yet.</p>
                <p className="text-xs text-muted-foreground">
                  Use the enrollment form to add the first target.
                </p>
              </div>
            )}
          </div>
        </div>
        <aside className="h-fit rounded-2xl border bg-card p-5 xl:sticky xl:top-6">
          <div className="flex items-center gap-2">
            <Plus className="size-5 text-emerald-300" />
            <h2 className="font-medium">Add a VM</h2>
          </div>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">
            Evesdropctl reads the SSH host key first. Nothing is trusted until you
            approve the fingerprint.
          </p>
          {pending ? (
            <div className="mt-5 space-y-4">
              <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-4">
                <div className="flex items-center gap-2 text-amber-200">
                  <Fingerprint className="size-4" />
                  <p className="text-sm font-medium">Verify host key</p>
                </div>
                <dl className="mt-3 space-y-2 text-xs">
                  <div>
                    <dt className="text-muted-foreground">Target</dt>
                    <dd>
                      {pending.host}:{pending.port}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Algorithm</dt>
                    <dd>{pending.algorithm}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">
                      SHA-256 fingerprint
                    </dt>
                    <dd className="mt-1 break-all font-mono text-amber-100">
                      {pending.fingerprint}
                    </dd>
                  </div>
                </dl>
              </div>
              <p className="flex gap-2 text-xs text-muted-foreground">
                <AlertTriangle className="size-4 shrink-0 text-amber-300" />
                Compare this fingerprint with a trusted source before accepting
                it.
              </p>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  disabled={busy}
                  onClick={() => void decide(false)}
                >
                  No, cancel
                </Button>
                <Button
                  type="button"
                  className="flex-1 bg-emerald-400 text-emerald-950"
                  disabled={busy}
                  onClick={() => void decide(true)}
                >
                  {busy && <LoaderCircle className="animate-spin" />}Yes, trust
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={discover} className="mt-5 space-y-4">
              <Field label="Display name">
                <Input
                  required
                  pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
                  value={form.name}
                  onChange={(e) => update('name', e.target.value)}
                  placeholder="web-prod-01"
                />
              </Field>
              <div className="grid grid-cols-[1fr_6rem] gap-3">
                <Field label="IP address or hostname">
                  <Input
                    required
                    value={form.hostname}
                    onChange={(e) => update('hostname', e.target.value)}
                    placeholder="192.168.0.110"
                  />
                </Field>
                <Field label="SSH port">
                  <Input
                    required
                    type="number"
                    min={1}
                    max={65535}
                    value={form.port}
                    onChange={(e) => update('port', e.target.value)}
                  />
                </Field>
              </div>
              <Field label="SSH username">
                <Input
                  required
                  value={form.username}
                  onChange={(e) => update('username', e.target.value)}
                  placeholder="sentinel"
                />
              </Field>
              <Field label="SSH password">
                <Input
                  required
                  type="password"
                  autoComplete="new-password"
                  value={form.password}
                  onChange={(e) => update('password', e.target.value)}
                  placeholder="Enter the VM account password"
                />
              </Field>
              <Field label="Environment classification">
                <select className="h-9 rounded-lg border bg-background px-3" value={form.environment} onChange={(e) => update('environment', e.target.value)}>
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                  <option value="disposable_lab">Disposable lab</option>
                </select>
              </Field>
              <p className="text-[11px] leading-5 text-muted-foreground">
                Encrypted locally before storage. It is never written to host
                configuration, browser storage, logs, or conversation history.
              </p>
              <Field label="Approved backup job IDs — one per line">
                <Textarea
                  className="min-h-16 font-mono text-xs"
                  value={form.backup_jobs}
                  onChange={(e) => update('backup_jobs', e.target.value)}
                  placeholder="database-dump"
                />
              </Field>
              <Field label="Approved log paths — one per line">
                <Textarea
                  required
                  className="min-h-24 font-mono text-xs"
                  value={form.allowed_logs}
                  onChange={(e) => update('allowed_logs', e.target.value)}
                />
              </Field>
              <Button type="submit" className="w-full" disabled={busy}>
                {busy && <LoaderCircle className="animate-spin" />}Connect and
                fetch key
              </Button>
            </form>
          )}
        </aside>
      </section>
      {classification && <div className="fixed inset-0 z-[80] grid place-items-center bg-black/70 p-4" role="dialog" aria-modal="true">
        <form onSubmit={classify} className="w-full max-w-md rounded-2xl border bg-card p-6 shadow-2xl">
          <h2 className="font-semibold">Classify {classification.host.name}</h2>
          <p className="mt-2 text-sm text-muted-foreground">Autonomous Lab is denied unless this host is development or disposable lab. Choose based on the VM's actual purpose.</p>
          <Field label="Environment"><select className="h-9 rounded-lg border bg-background px-3" value={classification.environment} onChange={(e) => setClassification({ ...classification, environment: e.target.value as Host['environment'] })}><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option><option value="disposable_lab">Disposable lab</option></select></Field>
          <div className="mt-4"><Field label="Administrator password"><Input required type="password" autoComplete="current-password" value={classification.password} onChange={(e) => setClassification({ ...classification, password: e.target.value })} /></Field></div>
          <div className="mt-5 flex justify-end gap-2"><Button type="button" variant="outline" disabled={busy} onClick={() => setClassification(null)}>Cancel</Button><Button type="submit" disabled={busy}>{busy && <LoaderCircle className="animate-spin" />}Save classification</Button></div>
        </form>
      </div>}
    </main>
  );
}
function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <Label className="grid gap-1.5 text-xs">
      {label}
      {children}
    </Label>
  );
}
