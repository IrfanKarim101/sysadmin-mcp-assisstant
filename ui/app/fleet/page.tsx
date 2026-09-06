'use client';

import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, RefreshCw, Server, ServerOff } from 'lucide-react';
import { AppNav } from '@/components/app-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiFetch } from '@/lib/api';

type NodeStatus = 'healthy' | 'warning' | 'offline';
type FleetNode = { name:string; hostname:string; status:NodeStatus; cpu_percent:number|null; memory_percent:number|null; disk_percent:number|null; message:string };

export default function FleetPage() {
  const [nodes, setNodes] = useState<FleetNode[]>([]);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  async function refresh() {
    setLoading(true); setError('');
    try {
      const identity = await apiFetch('/api/auth/me');
      if (!identity.ok) return;
      const user = await identity.json() as {csrf_token:string};
      sessionStorage.setItem('sentinel-csrf', user.csrf_token);
      const response = await apiFetch('/api/fleet/health');
      if (!response.ok) throw new Error('Fleet health request failed.');
      setNodes(await response.json() as FleetNode[]);
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not reach the agent API.'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void refresh(); }, []);
  const visible = useMemo(() => nodes.filter(node => `${node.name} ${node.hostname} ${node.status}`.toLowerCase().includes(query.toLowerCase())), [nodes, query]);
  const counts = { healthy:nodes.filter(n=>n.status==='healthy').length, warning:nodes.filter(n=>n.status==='warning').length, offline:nodes.filter(n=>n.status==='offline').length };
  return <main className="min-h-screen bg-background text-foreground">
    <header className="flex min-h-16 flex-wrap items-center justify-between gap-3 border-b px-6 py-3"><div><h1 className="font-semibold">Fleet health</h1><p className="text-xs text-muted-foreground">Bounded live snapshots across approved VMs</p></div><AppNav /></header>
    <section className="mx-auto max-w-7xl space-y-6 p-6">
      <div className="grid gap-3 sm:grid-cols-3">
        <Summary label="Healthy" value={counts.healthy} tone="healthy" /><Summary label="Warning" value={counts.warning} tone="warning" /><Summary label="Offline" value={counts.offline} tone="offline" />
      </div>
      <div className="flex gap-3"><Input aria-label="Search fleet" placeholder="Search VM, address, or state…" value={query} onChange={event=>setQuery(event.target.value)} /><Button type="button" variant="outline" onClick={refresh} disabled={loading}><RefreshCw className={loading?'animate-spin':''}/>Refresh</Button></div>
      {error && <p role="alert" className="rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200">{error}</p>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{visible.map(node=><article key={node.name} className="rounded-2xl border border-border bg-card p-5"><div className="flex items-start justify-between"><div className="flex gap-3"><div className="grid size-9 place-items-center rounded-xl bg-muted">{node.status==='offline'?<ServerOff className="size-4 text-red-300"/>:<Server className="size-4 text-emerald-300"/>}</div><div><h2 className="font-medium">{node.name}</h2><p className="text-xs text-muted-foreground">{node.hostname}</p></div></div><StatusBadge status={node.status}/></div><div className="mt-5 grid grid-cols-3 gap-2"><Metric label="CPU" value={node.cpu_percent}/><Metric label="Memory" value={node.memory_percent}/><Metric label="Disk" value={node.disk_percent}/></div><p className="mt-4 flex items-center gap-2 text-xs text-muted-foreground"><Activity className="size-3"/>{node.message}</p></article>)}{!loading&&!error&&!visible.length&&<p className="text-sm text-muted-foreground">No matching hosts.</p>}</div>
    </section>
  </main>;
}

function Summary({label,value,tone}:{label:string;value:number;tone:NodeStatus}) { return <div className="rounded-2xl border border-border bg-card p-4"><p className="text-xs text-muted-foreground">{label}</p><p className={`mt-1 text-2xl font-semibold ${tone==='healthy'?'text-emerald-300':tone==='warning'?'text-amber-300':'text-red-300'}`}>{value}</p></div> }
function Metric({label,value}:{label:string;value:number|null}) { return <div className="rounded-xl bg-muted/50 p-3"><p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p><p className="mt-1 font-mono text-sm">{value===null?'—':`${value}%`}</p></div> }
function StatusBadge({status}:{status:NodeStatus}) { return <Badge className={status==='healthy'?'bg-emerald-400/10 text-emerald-300':status==='warning'?'bg-amber-400/10 text-amber-300':'bg-red-400/10 text-red-300'}>{status==='warning'&&<AlertTriangle className="size-3"/>}{status}</Badge> }
