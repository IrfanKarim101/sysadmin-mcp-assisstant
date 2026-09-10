'use client';

import { useEffect, useMemo, useState } from 'react';
import { Trash2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { AppNav } from '@/components/app-nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiFetch } from '@/lib/api';

type Session = { id: string; host: string; provider: string; title: string; message_count: number };
type Message = { id: number; role: string; content: string };

export default function HistoryPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selected, setSelected] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [query, setQuery] = useState('');
  const [error, setError] = useState('');
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    void apiFetch('/api/auth/me').then(async (response) => {
      if (!response.ok) return;
      const identity = await response.json() as { csrf_token: string };
      sessionStorage.setItem('sentinel-csrf', identity.csrf_token);
      const history = await apiFetch('/api/chat/sessions');
      if (!history.ok) throw new Error('Could not load saved conversations.');
      const rows = await history.json() as Session[];
      setSessions(rows);
      setSelected(rows[0]?.id ?? '');
    }).catch(() => setError('The local agent API is offline. Start the backend and try again.'));
  }, []);

  useEffect(() => {
    if (!selected) { setMessages([]); return; }
    void apiFetch(`/api/chat/sessions/${selected}`)
      .then(async (response) => response.ok ? await response.json() as Message[] : [])
      .then(setMessages)
      .catch(() => setError('Could not load this conversation.'));
  }, [selected]);

  async function remove(session: Session) {
    if (!confirm(`Delete this conversation?\n\n${session.title}\n\nThis cannot be undone.`)) return;
    setDeleting(true); setError('');
    try {
      const response = await apiFetch(`/api/chat/sessions/${session.id}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('Could not delete this conversation.');
      const remaining = sessions.filter((item) => item.id !== session.id);
      setSessions(remaining);
      if (selected === session.id) setSelected(remaining[0]?.id ?? '');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not delete this conversation.');
    } finally { setDeleting(false); }
  }

  async function removeAll() {
    if (!sessions.length || !confirm(`Delete all ${sessions.length} saved conversations?\n\nThis cannot be undone.`)) return;
    setDeleting(true); setError('');
    try {
      const response = await apiFetch('/api/chat/sessions', { method: 'DELETE' });
      if (!response.ok) throw new Error('Could not delete conversation history.');
      setSessions([]); setSelected(''); setMessages([]);
      localStorage.removeItem('sentinel-session-id');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not delete conversation history.');
    } finally { setDeleting(false); }
  }

  const filtered = useMemo(() => sessions.filter((session) =>
    `${session.title} ${session.host} ${session.provider}`.toLowerCase().includes(query.toLowerCase())), [sessions, query]);

  return <main className="min-h-screen bg-background text-foreground">
    <header className="flex h-16 items-center justify-between border-b px-6">
      <div><h1 className="font-semibold">Conversation history</h1><p className="text-xs text-muted-foreground">Saved locally in SQLite</p></div>
      <div className="flex items-center gap-2"><Button variant="destructive" size="sm" disabled={!sessions.length || deleting} onClick={() => void removeAll()}><Trash2 />Delete all</Button><AppNav /></div>
    </header>
    {error && <p role="alert" className="border-b border-red-400/20 bg-red-400/10 px-6 py-3 text-sm text-red-200">{error}</p>}
    <div className="grid min-h-[calc(100vh-4rem)] md:grid-cols-[320px_1fr]">
      <aside className="border-r p-4"><Input aria-label="Search history" placeholder="Search host or conversation…" value={query} onChange={(event) => setQuery(event.target.value)} />
        <div className="mt-4 space-y-2">{filtered.map((session) => <div key={session.id} className={`flex rounded-xl border ${selected === session.id ? 'border-emerald-400/50 bg-emerald-400/5' : 'border-border'}`}>
          <button onClick={() => setSelected(session.id)} className="min-w-0 flex-1 p-3 text-left"><p className="truncate text-sm font-medium">{session.title}</p><p className="mt-1 text-xs text-muted-foreground">{session.host} · {session.provider} · {session.message_count} messages</p></button>
          <Button variant="ghost" size="icon" aria-label={`Delete ${session.title}`} disabled={deleting} onClick={() => void remove(session)} className="m-2 shrink-0 text-red-300"><Trash2 /></Button>
        </div>)}{!filtered.length && !error && <p className="p-3 text-sm text-muted-foreground">No saved conversations.</p>}</div>
      </aside>
      <section className="space-y-4 p-6">{messages.map((message) => <article key={message.id} className={`max-w-3xl rounded-2xl p-4 ${message.role === 'user' ? 'ml-auto bg-primary' : 'border bg-card'}`}><p className="mb-2 text-[10px] uppercase tracking-wider text-muted-foreground">{message.role}</p><div className="prose prose-invert max-w-none text-sm"><ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown></div></article>)}</section>
    </div>
  </main>;
}
