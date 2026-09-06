'use client';

import Link from 'next/link';
import { FormEvent, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, KeyRound, LoaderCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch } from '@/lib/api';

export default function ChangePassword() {
  const router = useRouter();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [forced, setForced] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void apiFetch('/api/auth/me')
      .then(async (response) => {
        if (!response.ok) return;
        const identity = await response.json() as { csrf_token: string; must_change_password: boolean };
        sessionStorage.setItem('sentinel-csrf', identity.csrf_token);
        setForced(identity.must_change_password);
      })
      .catch(() => setError('The local agent API is offline. Start the backend, then try again.'));
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (next !== confirm) { setError('New passwords do not match.'); return; }
    setBusy(true); setError('');
    try {
      const response = await apiFetch('/api/auth/change-password', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      const data = await response.json() as { detail?: string };
      if (!response.ok) throw new Error(data.detail ?? 'Could not change password');
      router.replace('/');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not reach the local agent API.');
    } finally { setBusy(false); }
  }

  return <main className="grid min-h-screen place-items-center bg-background p-6"><section className="w-full max-w-md rounded-2xl border border-border bg-card p-6">
    <div className="mb-5 flex size-10 items-center justify-center rounded-xl bg-emerald-400/10 text-emerald-300"><KeyRound /></div>
    <h1 className="text-xl font-semibold">{forced ? 'Create a secure password' : 'Change your password'}</h1>
    <p className="mt-2 text-sm text-muted-foreground">{forced ? 'This is required once because the temporary password is still active.' : 'Update your operator password. Use at least 12 characters.'}</p>
    <form onSubmit={submit} className="mt-6 space-y-4">
      <Label className="grid gap-2">Current password<Input required type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} /></Label>
      <Label className="grid gap-2">New password<Input required type="password" minLength={12} autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} /></Label>
      <Label className="grid gap-2">Confirm new password<Input required type="password" minLength={12} autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></Label>
      {error && <p role="alert" className="rounded-lg bg-red-400/10 px-3 py-2 text-sm text-red-200">{error}</p>}
      <Button type="submit" className="w-full" disabled={busy}>{busy && <LoaderCircle className="animate-spin" />}Change password</Button>
    </form>
    {!forced && <Link href="/" className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-4" />Back to console</Link>}
  </section></main>;
}
