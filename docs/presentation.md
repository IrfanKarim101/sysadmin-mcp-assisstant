# Phase 5: raw-first presentation

Every MCP result now contains these fields in order:

1. `raw` — exact command vectors, stdout, stderr, exit statuses, and truncation
   flags.
2. `summary` — a short additive explanation.
3. `display_markdown` — a ready-to-render raw-first view with the summary below.

Raw output is never replaced by a summary. The renderer chooses a Markdown
fence longer than any backtick run found in the raw data, preventing log lines
containing fake fences from escaping their code block.

## Summary boundary

`DiagnosticPresenter` depends on the small asynchronous `SummaryProvider`
protocol. Its default `SafeSummaryProvider` is deliberately content-blind: it
counts output lines and reports exit status, stderr, and truncation without
including or interpreting log text. This makes prompt-like log entries inert.

An LLM-backed provider can be added later without receiving executor or
transport access. Such a provider must treat results as untrusted data, return
only one to three sentences, and never omit the raw fields. The safe provider
remains the fallback when no LLM provider is configured.

Basic operational anomalies are currently flagged when commands fail, write to
stderr, or hit output limits. Host-specific CPU and memory thresholds belong in
the Phase 6 host configuration and are not yet applied.

Final visual validation depends on connecting a real MCP client/UI to the
disposable host. Confirm that the client renders `display_markdown`, or renders
the `raw` fields itself before showing `summary`.
