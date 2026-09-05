'use client';
import Link from 'next/link';
import { History, LogOut, TerminalSquare } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { apiFetch } from '@/lib/api';

export function AppNav() {
  async function logout() {
    await apiFetch('/api/auth/logout', { method: 'POST' });
    sessionStorage.removeItem('sentinel-csrf');
    location.assign('/login');
  }
  return <nav className="flex items-center gap-2" aria-label="Primary navigation">
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/"><TerminalSquare className="size-4"/>Console</Link>
    <Link className="inline-flex h-8 items-center gap-2 rounded-md px-3 text-sm hover:bg-accent" href="/history"><History className="size-4"/>History</Link>
    <Button variant="ghost" size="sm" onClick={logout}><LogOut />Sign out</Button>
  </nav>;
}
