'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { LoaderCircle, ShieldCheck } from 'lucide-react';
import { API } from '@/lib/api';

type Identity = { csrf_token: string; must_change_password: boolean };

export function AuthGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let active = true;
    setReady(false);
    setOffline(false);

    void fetch(`${API}/api/auth/me`, {
      credentials: 'include',
      headers: { accept: 'application/json' },
      cache: 'no-store',
    }).then(async (response) => {
      if (!active) return;
      if (response.status === 401) {
        sessionStorage.removeItem('sentinel-csrf');
        if (pathname !== '/login') router.replace('/login');
        else setReady(true);
        return;
      }
      if (!response.ok) throw new Error(`Authentication check returned ${response.status}`);
      const identity = await response.json() as Identity;
      if (!active) return;
      sessionStorage.setItem('sentinel-csrf', identity.csrf_token);
      if (identity.must_change_password && pathname !== '/change-password') {
        router.replace('/change-password');
      } else if (pathname === '/login') {
        router.replace(identity.must_change_password ? '/change-password' : '/');
      } else {
        setReady(true);
      }
    }).catch(() => {
      if (!active) return;
      if (pathname === '/login') setReady(true);
      else setOffline(true);
    });

    return () => { active = false; };
  }, [pathname, router]);

  if (ready) return children;
  return <AuthSplash offline={offline} onRetry={() => location.reload()} />;
}

function AuthSplash({ offline, onRetry }: { offline: boolean; onRetry: () => void }) {
  return <main className="grid min-h-screen place-items-center bg-background p-6">
    <section className="flex max-w-sm flex-col items-center text-center" role="status" aria-live="polite">
      <div className="relative grid size-20 place-items-center rounded-3xl border border-emerald-400/20 bg-emerald-400/10 text-emerald-300 shadow-2xl shadow-emerald-950/30">
        <ShieldCheck className="size-9" />
        {!offline && <LoaderCircle className="absolute -bottom-2 -right-2 size-6 animate-spin rounded-full bg-background p-1" />}
      </div>
      <h1 className="mt-6 text-xl font-semibold tracking-tight">Evesdropctl</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        {offline ? 'The secure backend is unavailable.' : 'Verifying your secure session…'}
      </p>
      {offline && <button type="button" onClick={onRetry} className="mt-5 rounded-lg border border-border px-4 py-2 text-sm hover:bg-accent">Retry connection</button>}
    </section>
  </main>;
}
