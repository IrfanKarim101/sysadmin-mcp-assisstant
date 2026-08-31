# Phase 4: MCP server

The MCP adapter exposes exactly six tools over stdio:

- `check_ports`
- `check_services`
- `check_resources`
- `read_log`
- `grep_log`
- `who_is_on`

There is no raw command, argv, shell, SSH, or generic execution tool. Inputs
use generated JSON schemas with service/log-mode enums, 1–500 line bounds, and
1–256 character grep-pattern bounds. The executor independently repeats all
security validation.

Every tool is annotated read-only, non-destructive, and idempotent. Results
contain the exact command vector, stdout, stderr, exit status, and truncation
flag. Multiple-command capabilities return an ordered `results` collection.
Raw diagnostic output is untrusted content and must not be interpreted as
instructions.

## Run over stdio

Create `config/hosts.toml` from the example and use exact log paths. Then run:

```sh
sysadmin-mcp --config config/hosts.toml --audit-db data/audit.db
```

The server writes no startup text to stdout because stdout carries the MCP
protocol. SSH actions fail closed if the mandatory audit sink cannot commit the
initial attempt event.

The executable currently supports stdio only. Keep it behind a local MCP host;
do not expose it as an unauthenticated network service.

## Validation

Unit tests enumerate the complete exposed tool set, inspect generated schemas
and annotations, invoke every tool through the MCP SDK, and assert the exact
argv received by a fake transport. They also verify that injection-shaped
patterns remain data and disallowed paths cannot reach transport.

Final live validation requires the disposable Linux host from Phases 0 and 2.
After it is available, connect an MCP client and try representative prompts:

- “Check what is listening on the test host.”
- “Show failed services on the test host.”
- “Tail 20 lines from `/var/log/syslog`.”
- “Search `/var/log/syslog` for 502 responses.”
- “Who is logged in?”

Confirm the resulting tool names and audit events, then repeat with a
non-allowlisted path and an oversized line request and confirm denial.
