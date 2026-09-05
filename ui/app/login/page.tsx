'use client';
import { FormEvent, useState } from 'react';
import { useRouter } from 'next/navigation';
import { LockKeyhole, LoaderCircle, TerminalSquare } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { API } from '@/lib/api';

export default function Login() {
  const router = useRouter();
  const [username, setUsername] = useState('admin'), [password, setPassword] = useState('');
  const [error, setError] = useState(''), [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await fetch(`${API}/api/auth/login`, { method: 'POST', credentials: 'include', headers: {'content-type':'application/json'}, body: JSON.stringify({username, password}) });
      const data = await response.json() as {detail?:string;csrf_token:string;must_change_password:boolean};
      if (!response.ok) throw new Error(data.detail ?? 'Sign in failed');
      sessionStorage.setItem('sentinel-csrf', data.csrf_token);
      router.replace(data.must_change_password ? '/change-password' : '/');
    } catch (e) { setError(e instanceof Error ? e.message : 'Sign in failed'); }
    finally { setBusy(false); }
  }
  return <main className="grid min-h-screen place-items-center bg-background p-6"><section className="w-full max-w-sm rounded-2xl border border-border bg-card p-6 shadow-2xl">
    <div className="mb-6 flex items-center gap-3"><div className="grid size-10 place-items-center rounded-xl bg-emerald-400/10 text-emerald-300"><TerminalSquare /></div><div><h1 className="font-semibold">Sentinel Ops</h1><p className="text-xs text-muted-foreground">Secure operator sign in</p></div></div>
    <form className="space-y-4" onSubmit={submit}><Label className="grid gap-2">Username<Input autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} /></Label><Label className="grid gap-2">Password<Input type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} /></Label>
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}<Button className="w-full bg-emerald-400 text-emerald-950" disabled={busy}>{busy?<LoaderCircle className="animate-spin"/>:<LockKeyhole/>}Sign in</Button></form>
    <p className="mt-5 text-xs text-muted-foreground">First login: <code>admin</code> / <code>admin</code>. You must replace it before accessing diagnostics.</p>
  </section></main>;
}
