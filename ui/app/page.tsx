'use client';
import { FormEvent, useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  Activity,
  Bot,
  CheckCircle2,
  Database,
  LoaderCircle,
  LockKeyhole,
  Network,
  Send,
  Server,
  ShieldCheck,
  TerminalSquare,
  Users,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
const API = process.env.NEXT_PUBLIC_AGENT_API_URL ?? 'http://127.0.0.1:8765';
const actions = [
  ['Open ports', 'Check open ports and flag anything unusual', Network],
  ['Failed services', 'Show failed services', Activity],
  ['Resources', 'Check CPU and memory usage', Database],
  ['Active users', 'Who is logged in?', Users],
] as const;
type Host = { name: string; hostname: string; allowed_logs: string[] };
type Result = {
  command: string[];
  stdout: string;
  stderr: string;
  exit_status: number;
  truncated: boolean;
};
type Evt = {
  type: string;
  message?: string;
  tool?: string;
  results?: Result[];
  summary?: string;
  session_id?: string;
};
type Turn = { role: 'user' | 'agent'; text?: string; events?: Evt[] };
type SavedMessage = { role: 'user' | 'assistant'; content: string };
type ProviderId = 'openai' | 'gemini';
type Provider = {
  id: string;
  label: string;
  enabled: boolean;
  configured: boolean;
};
export default function Home() {
  const [hosts, setHosts] = useState<Host[]>([]),
    [host, setHost] = useState(''),
    [message, setMessage] = useState('');
  const [turns, setTurns] = useState<Turn[]>([]),
    [running, setRunning] = useState(false),
    [online, setOnline] = useState(false);
  const [provider, setProvider] = useState<ProviderId>('openai'),
    [providers, setProviders] = useState<Provider[]>([]);
  const [sessionId, setSessionId] = useState('');
  useEffect(() => {
    const storedSession =
      window.localStorage.getItem('sentinel-session-id') ?? crypto.randomUUID();
    window.localStorage.setItem('sentinel-session-id', storedSession);
    setSessionId(storedSession);
    Promise.all([
      fetch(`${API}/api/hosts`).then((r) =>
        r.ok ? r.json() : Promise.reject(),
      ),
      fetch(`${API}/api/providers`).then((r) =>
        r.ok ? r.json() : Promise.reject(),
      ),
      fetch(`${API}/api/chat/sessions/${storedSession}`).then((r) =>
        r.ok ? r.json() : Promise.reject(),
      ),
    ])
      .then(([x, p, saved]: [Host[], Provider[], SavedMessage[]]) => {
        setHosts(x);
        setHost(x[0]?.name ?? '');
        setProviders(p);
        setTurns(
          saved.map((item) =>
            item.role === 'user'
              ? { role: 'user', text: item.content }
              : {
                  role: 'agent',
                  events: [{ type: 'summary', message: item.content }],
                },
          ),
        );
        setOnline(true);
      })
      .catch(() => setOnline(false));
  }, []);
  async function submit(e: FormEvent) {
    e.preventDefault();
    const prompt = message.trim();
    if (!prompt || !host || running) return;
    setMessage('');
    setRunning(true);
    setTurns((x) => [
      ...x,
      { role: 'user', text: prompt },
      { role: 'agent', events: [] },
    ]);
    try {
      const r = await fetch(`${API}/api/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          message: prompt,
          host,
          provider,
          session_id: sessionId,
        }),
      });
      if (!r.ok || !r.body) throw Error(`Agent API returned ${r.status}`);
      const reader = r.body.getReader(),
        decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        for (const line of lines)
          if (line.trim()) {
            const item = JSON.parse(line) as Evt;
            if (item.type === 'session') {
              if (item.session_id) {
                setSessionId(item.session_id);
                window.localStorage.setItem(
                  'sentinel-session-id',
                  item.session_id,
                );
              }
              continue;
            }
            if (item.type === 'done') setRunning(false);
            setTurns((x) => [
              ...x.slice(0, -1),
              { role: 'agent', events: [...(x.at(-1)?.events ?? []), item] },
            ]);
          }
      }
    } catch (err) {
      const item: Evt = {
        type: 'error',
        message: err instanceof Error ? err.message : 'Connection failed',
      };
      setTurns((x) => [
        ...x.slice(0, -1),
        { role: 'agent', events: [...(x.at(-1)?.events ?? []), item] },
      ]);
    } finally {
      setRunning(false);
    }
  }
  const selected = hosts.find((x) => x.name === host),
    latest = turns.filter((x) => x.role === 'agent').at(-1)?.events ?? [];
  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="flex h-16 items-center justify-between border-b border-border bg-card/70 px-6">
        <div className="flex items-center gap-3">
          <div className="grid size-9 place-items-center rounded-xl bg-emerald-400/10 text-emerald-300">
            <TerminalSquare className="size-4" />
          </div>
          <div>
            <div className="flex gap-2 text-sm font-semibold">
              Sentinel Ops{' '}
              <Badge className="bg-emerald-500/10 text-[10px] text-emerald-300">
                READ ONLY
              </Badge>
            </div>
            <p className="text-[11px] text-muted-foreground">
              Sysadmin MCP agent
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span
            className={`size-1.5 rounded-full ${online ? 'bg-emerald-400' : 'bg-red-400'}`}
          />
          {online ? 'Agent connected' : 'Agent offline'}
          <NativeSelect
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="w-44"
          >
            {hosts.map((x) => (
              <NativeSelectOption key={x.name} value={x.name}>
                {x.name}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </div>
      </header>
      <div className="grid min-h-[calc(100vh-4rem)] lg:grid-cols-[220px_minmax(0,1fr)_280px]">
        <aside className="hidden border-r border-border p-4 lg:flex lg:flex-col">
          <p className="px-2 pb-3 text-[10px] uppercase tracking-[.18em] text-muted-foreground">
            Diagnostics
          </p>
          {actions.map(([label, prompt, Icon]) => (
            <button
              key={label}
              onClick={() => setMessage(prompt)}
              className="flex items-center gap-3 rounded-lg px-2 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-foreground"
            >
              <Icon className="size-4 text-emerald-300" />
              {label}
            </button>
          ))}
          <div className="mt-auto rounded-xl border border-border p-3 text-[11px] text-muted-foreground">
            <b className="mb-2 flex gap-2 text-foreground">
              <ShieldCheck className="size-4 text-emerald-300" />
              Policy enforced
            </b>
            Six fixed tools. Bounded, allowlisted, audited.
            <p className="mt-2 text-emerald-300">Chat history saved locally</p>
          </div>
        </aside>
        <section className="flex min-w-0 flex-col">
          <ScrollArea className="h-[calc(100vh-13.5rem)] min-h-[470px]">
            <div className="mx-auto max-w-4xl space-y-7 px-6 py-8">
              <Bubble>
                Ready to inspect{' '}
                <b className="text-emerald-300">
                  {host || 'a configured host'}
                </b>
                . Ask about ports, services, resources, logs, or users.
              </Bubble>
              {turns.map((t, i) =>
                t.role === 'user' ? (
                  <div key={i} className="flex justify-end">
                    <div className="max-w-xl rounded-2xl rounded-tr-sm bg-primary px-4 py-3 text-sm">
                      {t.text}
                    </div>
                  </div>
                ) : (
                  <Bubble key={i}>
                    <Events events={t.events ?? []} />
                  </Bubble>
                ),
              )}
            </div>
          </ScrollArea>
          <div className="border-t border-border p-4">
            <form
              onSubmit={submit}
              className="mx-auto max-w-4xl rounded-2xl border border-border bg-card/80 p-2"
            >
              <div
                className="flex items-center gap-1 px-1 pb-1"
                role="group"
                aria-label="LLM provider"
              >
                {providers.map((p) => (
                  <Button
                    key={p.id}
                    type="button"
                    size="sm"
                    variant={provider === p.id ? 'secondary' : 'ghost'}
                    disabled={!p.enabled || running}
                    title={
                      !p.enabled
                        ? 'Coming soon'
                        : p.configured
                          ? 'API key configured'
                          : 'Add API key to .env'
                    }
                    onClick={() => p.enabled && setProvider(p.id as ProviderId)}
                    className="h-7 text-[11px]"
                  >
                    {p.label}
                    {!p.enabled && (
                      <span className="ml-1 text-[9px] opacity-60">Soon</span>
                    )}
                    {p.enabled && (
                      <span
                        className={`ml-1 size-1.5 rounded-full ${p.configured ? 'bg-emerald-400' : 'bg-amber-400'}`}
                      />
                    )}
                  </Button>
                ))}
              </div>
              <Textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder={
                  online
                    ? 'Ask Sentinel to inspect this host…'
                    : 'Start sysadmin-web to connect…'
                }
                className="min-h-14 resize-none border-0 bg-transparent"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    e.currentTarget.form?.requestSubmit();
                  }
                }}
              />
              <div className="flex justify-between px-1">
                <span className="flex items-center gap-2 text-[10px] text-muted-foreground">
                  <LockKeyhole className="size-3" />
                  Keys stay in the server-side .env file
                </span>
                <Button
                  type="submit"
                  disabled={!online || !message.trim() || running}
                  className="bg-emerald-400 text-emerald-950"
                >
                  {running ? (
                    <LoaderCircle className="animate-spin" />
                  ) : (
                    <Send />
                  )}
                  {running
                    ? 'Working'
                    : `Run with ${provider === 'openai' ? 'OpenAI' : 'Gemini'}`}
                </Button>
              </div>
            </form>
          </div>
        </section>
        <aside className="hidden border-l border-border p-4 xl:block">
          <h2 className="mb-4 flex gap-2 text-xs font-semibold">
            <Activity className="size-4" />
            Live activity
          </h2>
          <div className="space-y-3 text-[11px]">
            {latest.length ? (
              latest.map((e, i) => (
                <div key={i}>
                  <p className="text-emerald-300">
                    {e.tool ?? e.type.replace('_', ' ')}
                  </p>
                  <p className="text-muted-foreground">
                    {e.message ?? e.summary}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-muted-foreground">
                Actions appear here as they run.
              </p>
            )}
          </div>
          <div className="mt-6 rounded-xl border border-border p-3 text-[11px] text-muted-foreground">
            <Server className="mr-2 inline size-4" />
            {selected?.hostname ?? 'No host'}
            <p className="mt-2 text-emerald-300">
              {selected
                ? `${selected.allowed_logs.length} allowlisted logs`
                : 'Offline'}
            </p>
          </div>
        </aside>
      </div>
    </main>
  );
}
function Bubble({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3">
      <div className="grid size-8 shrink-0 place-items-center rounded-lg border border-border text-emerald-300">
        <Bot className="size-4" />
      </div>
      <div className="min-w-0 flex-1 rounded-2xl rounded-tl-sm border border-border bg-card/75 p-4 text-sm leading-6">
        {children}
      </div>
    </div>
  );
}
function Events({ events }: { events: Evt[] }) {
  if (!events.length)
    return (
      <span className="flex gap-2 text-muted-foreground">
        <LoaderCircle className="size-4 animate-spin" />
        Starting…
      </span>
    );
  const finished = events.some((event) =>
    ['done', 'error', 'summary'].includes(event.type),
  );
  return (
    <div className="space-y-3">
      {events.map((e, i) =>
        e.type === 'tool_result' ? (
          <div key={i} className="space-y-2">
            {e.results?.map((r, j) => (
              <div
                key={j}
                className="overflow-hidden rounded-xl border border-border bg-black/20"
              >
                <div className="border-b border-border px-3 py-2 font-mono text-[11px] text-muted-foreground">
                  $ {r.command.join(' ')}
                </div>
                <pre className="max-h-72 overflow-auto p-3 font-mono text-[11px] text-zinc-300">
                  {r.stdout || r.stderr || '(no output)'}
                </pre>
              </div>
            ))}
          </div>
        ) : e.type === 'thinking' ? (
          <p key={i} className="flex gap-2 text-muted-foreground">
            {finished ? (
              <CheckCircle2 className="size-4 text-emerald-300" />
            ) : (
              <LoaderCircle className="size-4 animate-spin" />
            )}
            {finished ? 'Diagnostic plan completed.' : e.message}
          </p>
        ) : e.type === 'summary' ? (
          <MarkdownReport key={i}>{e.message ?? ''}</MarkdownReport>
        ) : e.type === 'error' ? (
          <p key={i} className="text-red-300">
            {e.message}
          </p>
        ) : e.type === 'done' ? null : (
          <p
            key={i}
            className={
              e.type === 'tool_start' ? 'text-xs text-emerald-300' : ''
            }
          >
            {e.message ??
              (e.type === 'tool_start'
                ? `Running ${e.tool} with policy validation…`
                : null)}
          </p>
        ),
      )}
    </div>
  );
}

function MarkdownReport({ children }: { children: string }) {
  return (
    <div className="space-y-3 text-sm leading-6 text-zinc-300">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h2 className="text-base font-semibold text-foreground">{children}</h2>
          ),
          h2: ({ children }) => (
            <h3 className="border-b border-border/70 pb-1 text-sm font-semibold text-foreground">
              {children}
            </h3>
          ),
          h3: ({ children }) => (
            <h4 className="text-sm font-semibold text-emerald-300">{children}</h4>
          ),
          p: ({ children }) => <p>{children}</p>,
          ul: ({ children }) => <ul className="list-disc space-y-1 pl-5">{children}</ul>,
          ol: ({ children }) => <ol className="list-decimal space-y-2 pl-5">{children}</ol>,
          li: ({ children }) => <li className="pl-1">{children}</li>,
          strong: ({ children }) => (
            <strong className="font-semibold text-foreground">{children}</strong>
          ),
          code: ({ children }) => (
            <code className="rounded bg-black/30 px-1.5 py-0.5 font-mono text-[11px] text-emerald-200">
              {children}
            </code>
          ),
          hr: () => <hr className="border-border/70" />,
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
