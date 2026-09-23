'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import {
  DatabaseBackup,
  History,
  LogOut,
  Menu,
  MonitorCog,
  Server,
  ShieldCheck,
  TerminalSquare,
  UserRound,
  Workflow,
  Wrench,
  GitPullRequestDraft,
  X,
  Package,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { apiFetch } from '@/lib/api';

const links = [
  ['/', 'Console', TerminalSquare],
  ['/fleet', 'Fleet', Server],
  ['/vms', 'VM management', MonitorCog],
  ['/playbooks', 'Playbooks', Workflow],
  ['/security', 'Security', ShieldCheck],
  ['/remediation', 'Remediation', Wrench],
  ['/changes', 'Changes', GitPullRequestDraft],
  ['/software', 'Software', Package],
  ['/scripts', 'Host scripts', TerminalSquare],
  ['/dynamic', 'Dynamic scripts', TerminalSquare],
  ['/backups', 'Database backups', DatabaseBackup],
  ['/history', 'History', History],
  ['/account', 'Account', UserRound],
] as const;

const subscribe = () => () => {};
const clientSnapshot = () => true;
const serverSnapshot = () => false;

export function AppNav() {
  const mounted = useSyncExternalStore(subscribe, clientSnapshot, serverSnapshot);
  const path = usePathname(),
    [open, setOpen] = useState(false);
  async function logout() {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
    } finally {
      sessionStorage.removeItem('sentinel-csrf');
      localStorage.removeItem('sentinel-session-id');
      location.replace('/login');
    }
  }
  return (
    <>
      <span className="sentinel-nav-anchor" hidden />
      {mounted && createPortal(<>
      <Button
        type="button"
        variant="outline"
        size="icon"
        aria-label="Open navigation"
        className="fixed left-3 top-3 z-50 md:hidden"
        onClick={() => setOpen(true)}
      >
        <Menu />
      </Button>
      {open && (
        <button
          type="button"
          aria-label="Close navigation overlay"
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={() => setOpen(false)}
        />
      )}
      <aside
        className={`sentinel-drawer fixed inset-y-0 left-0 z-50 flex w-60 flex-col overflow-y-auto border-r border-border bg-card/95 p-4 backdrop-blur transition-transform md:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <div className="flex items-center gap-3 border-b border-border pb-4">
          <div className="grid size-9 place-items-center rounded-xl bg-emerald-400/10 text-emerald-300">
            <ShieldCheck className="size-5" />
          </div>
          <div>
            <p className="text-sm font-semibold">Evesdropctl</p>
            <p className="text-[11px] text-muted-foreground">
              Bounded control plane
            </p>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ml-auto md:hidden"
            aria-label="Close navigation"
            onClick={() => setOpen(false)}
          >
            <X />
          </Button>
        </div>
        <nav
          className="mt-5 flex flex-1 flex-col gap-1"
          aria-label="Primary navigation"
        >
          {links.map(([href, label, Icon]) => {
            const active = href === '/' ? path === href : path.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                onClick={() => setOpen(false)}
                className={`flex h-10 items-center gap-3 rounded-xl px-3 text-sm transition-colors ${active ? 'bg-emerald-400/10 text-emerald-200' : 'text-muted-foreground hover:bg-accent hover:text-foreground'}`}
              >
                <Icon className="size-4" />
                {label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border pt-4">
          <Button
            variant="ghost"
            className="w-full justify-start text-muted-foreground"
            onClick={logout}
          >
            <LogOut />
            Sign out
          </Button>
          <p className="mt-3 px-3 text-[10px] leading-4 text-muted-foreground">
            Host changes require scoped authority and confirmation.
          </p>
        </div>
      </aside>
      </>, document.body)}
    </>
  );
}
