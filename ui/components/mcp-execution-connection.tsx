'use client';
import { useState } from 'react';
import { apiFetch } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export function MCPExecutionConnection() {
  const [token, setToken] = useState(''), [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function connect() {
    setBusy(true); setToken(''); setMessage('');
    try {
      const response = await apiFetch('/api/scripts/mcp-connection', { method: 'POST' });
      const data = await response.json() as { token?: string; expires_at?: string; detail?: string };
      if (!response.ok || !data.token) throw new Error(data.detail ?? 'Could not connect MCP.');
      setToken(data.token); setMessage(`Connection expires with this armed session (${data.expires_at}).`);
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Connection failed.'); }
    finally { setBusy(false); }
  }
  return <section className="glass-panel space-y-3 rounded-2xl border p-5 text-sm">
    <h2 className="font-semibold">Connect your MCP agent</h2>
    <p className="text-muted-foreground">This delegates the currently armed session to your MCP client. Every host job requires your approval here before execution, including Autonomous Lab jobs. Disable or re-arm the mode to revoke the connection.</p>
    <Button disabled={busy} onClick={() => void connect()}>Create MCP connection</Button>
    {token && <><Input aria-label="MCP execution token" type="password" readOnly value={token} />
      <Button variant="outline" onClick={() => { void navigator.clipboard.writeText(token).then(() => setMessage('Token copied. Store it in your MCP client environment, not a chat message.')).catch(() => setMessage('Clipboard unavailable. Select the token field and copy manually.')); }}>Copy token</Button>
      <p>Set <code>SYSADMIN_MCP_EXECUTION_TOKEN</code> in your MCP client environment, then restart its server with:</p>
      <pre className="overflow-auto rounded-lg bg-black/30 p-3 text-xs">sysadmin-mcp --enable-host-scripts</pre>
      <p className="text-muted-foreground">The MCP server must run on the same machine as this backend. Never paste the token into the model conversation. Creating another connection revokes the previous token.</p></>}
    {message && <output className="block">{message}</output>}
  </section>;
}
