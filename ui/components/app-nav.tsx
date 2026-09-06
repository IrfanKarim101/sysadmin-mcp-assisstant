'use client';
import Link from 'next/link';
import { History, KeyRound, LogOut, Server, ShieldCheck, TerminalSquare, Workflow } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { apiFetch } from '@/lib/api';

export function AppNav() {
  async function logout() {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Fail closed in the browser when the local API has stopped.
    } finally {
      sessionStorage.removeItem('sentinel-csrf');
      localStorage.removeItem('sentinel-session-id');
      location.replace('/login');
    }
  }
  return <nav className="flex items-center gap-2" aria-label="Primary navigation">
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/"><TerminalSquare className="size-4"/>Console</Link>
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/fleet"><Server className="size-4"/>Fleet</Link>
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/playbooks"><Workflow className="size-4"/>Playbooks</Link>
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/security"><ShieldCheck className="size-4"/>Security</Link>
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/history"><History className="size-4"/>History</Link>
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/change-password"><KeyRound className="size-4"/>Password</Link>
    <Button variant="ghost" size="sm" onClick={logout}><LogOut />Sign out</Button>
  </nav>;
}
