'use client';
import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  DatabaseBackup,
  KeyRound,
  LoaderCircle,
  ShieldCheck,
} from 'lucide-react';
import { AppNav } from '@/components/app-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { apiFetch } from '@/lib/api';

type JobSet = { host: string; backup_jobs: string[] };
type Preview = {
  approval_token: string;
  expires_in_seconds: number;
  host: string;
  job: string;
  effect: string;
};
type Result = {
  stdout: string;
  stderr: string;
  exit_status: number;
  truncated: boolean;
};
type Outcome = { host: string; job: string; result: Result; verified: boolean };

export default function BackupsPage() {
  const [sets, setSets] = useState<JobSet[]>([]),
    [host, setHost] = useState(''),
    [job, setJob] = useState(''),
    [password, setPassword] = useState(''),
    [preview, setPreview] = useState<Preview | null>(null),
    [outcome, setOutcome] = useState<Outcome | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const jobs = useMemo(
    () => sets.find((x) => x.host === host)?.backup_jobs ?? [],
    [sets, host],
  );
  useEffect(() => {
    void (async () => {
      try {
        const me = await apiFetch('/api/auth/me');
        if (!me.ok) return;
        const identity = (await me.json()) as { csrf_token: string };
        sessionStorage.setItem('sentinel-csrf', identity.csrf_token);
        const response = await apiFetch('/api/backups/jobs');
        const data = (await response.json()) as JobSet[] & { detail?: string };
        if (!response.ok)
          throw new Error(
            (data as { detail?: string }).detail ??
              'Could not load backup policy.',
          );
        setSets(data);
        const first = data.find((x) => x.backup_jobs.length);
        setHost(first?.host ?? data[0]?.host ?? '');
        setJob(first?.backup_jobs[0] ?? '');
      } catch (reason) {
        setError(
          reason instanceof Error ? reason.message : 'Agent API is offline.',
        );
      }
    })();
  }, []);
  function chooseHost(value: string) {
    setHost(value);
    setJob(sets.find((x) => x.host === value)?.backup_jobs[0] ?? '');
    setPreview(null);
    setOutcome(null);
  }
  async function createPreview(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setOutcome(null);
    try {
      const response = await apiFetch('/api/backups/preview', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ host, job, password }),
      });
      const data = (await response.json()) as Preview & { detail?: string };
      setPassword('');
      if (!response.ok) throw new Error(data.detail ?? 'Preview was denied.');
      setPreview(data);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : 'Could not create approval.',
      );
    } finally {
      setBusy(false);
    }
  }
  async function execute() {
    if (!preview || busy) return;
    setBusy(true);
    setError('');
    try {
      const response = await apiFetch('/api/backups/execute', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ approval_token: preview.approval_token }),
      });
      const data = (await response.json()) as Outcome & { detail?: string };
      if (!response.ok) throw new Error(data.detail ?? 'Backup was denied.');
      setOutcome(data);
      setPreview(null);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : 'Could not run the backup.',
      );
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }
  const available = sets.some((x) => x.backup_jobs.length);
  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="flex min-h-16 items-center justify-between border-b px-6 py-3">
        <div>
          <h1 className="font-semibold">Database backups</h1>
          <p className="text-xs text-muted-foreground">
            Run fixed, root-approved dump scripts with an audit trail
          </p>
        </div>
        <AppNav />
      </header>
      <section className="mx-auto max-w-5xl space-y-6 p-6">
        <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-4">
          <div className="flex gap-3">
            <ShieldCheck className="size-5 shrink-0 text-emerald-300" />
            <div>
              <p className="text-sm font-medium text-emerald-100">
                Script paths stay on the VM
              </p>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
              The UI sends only a reviewed job ID. The root-owned host policy
              maps that ID to a fixed script and rejects arbitrary
                paths, arguments, and shell syntax.
              </p>
            </div>
          </div>
        </div>
        {error && (
          <p
            role="alert"
          className="rounded-xl bg-red-400/10 p-4 text-sm text-red-200"
          >
            {error}
          </p>
        )}
        {!available ? (
          <div className="rounded-2xl border border-dashed p-10 text-center">
            <DatabaseBackup className="mx-auto size-7 text-muted-foreground" />
            <h2 className="mt-3 font-medium">No backup jobs enabled</h2>
            <p className="mx-auto mt-2 max-w-lg text-sm text-muted-foreground">
              Enable the database-dump job in the host configuration and VM
              policy.
            </p>
          </div>
        ) : (
          <div className="grid gap-6 lg:grid-cols-2">
            <form
              onSubmit={createPreview}
              className="h-fit space-y-4 rounded-2xl border bg-card p-5"
            >
              <div className="flex items-center gap-2">
                <DatabaseBackup className="size-5 text-emerald-300" />
                <h2 className="font-medium">Run an approved dump</h2>
              </div>
              <Label className="grid gap-2 text-xs">
                Host
                <NativeSelect
                  value={host}
                  onChange={(e) => chooseHost(e.target.value)}
                >
                  {sets
                    .filter((x) => x.backup_jobs.length)
                    .map((x) => (
                      <NativeSelectOption key={x.host} value={x.host}>
                        {x.host}
                      </NativeSelectOption>
                    ))}
                </NativeSelect>
              </Label>
              <Label className="grid gap-2 text-xs">
                Backup job
                <NativeSelect
                  value={job}
                  onChange={(e) => {
                    setJob(e.target.value);
                    setPreview(null);
                  }}
                >
                  {jobs.map((x) => (
                    <NativeSelectOption key={x} value={x}>
                      {x}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </Label>
              <Label className="grid gap-2 text-xs">
                Re-enter your password
                <Input
                  required
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </Label>
              <Button type="submit" className="w-full" disabled={busy || !job}>
                {busy ? (
                  <LoaderCircle className="animate-spin" />
                ) : (
                  <KeyRound />
                )}
                Authenticate and preview
              </Button>
            </form>
            <div className="space-y-4">
              {preview && (
                <article className="rounded-2xl border border-amber-400/25 bg-card p-5">
                  <div className="flex items-center justify-between">
                    <h2 className="font-medium">Effect preview</h2>
                    <Badge className="bg-amber-400/10 text-amber-200">
                      Expires in {preview.expires_in_seconds}s
                    </Badge>
                  </div>
                  <p className="mt-3 text-sm">{preview.effect}</p>
                  <p className="mt-2 flex gap-2 text-xs text-amber-200">
                    <AlertTriangle className="size-4 shrink-0" />
                    Confirm that the VM has enough free space before starting a
                    large dump.
                  </p>
                  <div className="mt-4 flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      className="flex-1"
                      onClick={() => setPreview(null)}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="button"
                      className="flex-1 bg-amber-400 text-amber-950"
                      disabled={busy}
                      onClick={() => void execute()}
                    >
                      {busy && <LoaderCircle className="animate-spin" />}Confirm
                      backup
                    </Button>
                  </div>
                </article>
              )}
              {outcome && (
                <article className="rounded-2xl border border-emerald-400/25 bg-card p-5">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="size-5 text-emerald-300" />
                    <h2 className="font-medium">
                      {outcome.verified ? 'Backup completed' : 'Backup failed'}
                    </h2>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    {outcome.job} on {outcome.host} · exit status{' '}
                    {outcome.result.exit_status}
                  </p>
                  <details className="mt-4 rounded-xl border bg-black/20 p-3">
                    <summary className="cursor-pointer text-xs font-medium">
                      Script output
                    </summary>
                    <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-zinc-300">
                      {outcome.result.stdout ||
                        outcome.result.stderr ||
                        '(no output)'}
                    </pre>
                    {outcome.result.truncated && (
                      <p className="mt-2 text-xs text-amber-200">
                        Output was truncated at the configured safety limit.
                      </p>
                    )}
                  </details>
                </article>
              )}
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
