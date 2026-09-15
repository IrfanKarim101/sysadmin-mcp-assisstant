# Package Rollback Limitations

Package operations are not assumed to be fully reversible. Approval previews
must show these limitations before any future live adapter is enabled.

| Scenario | Automatic rollback | Required response |
| --- | --- | --- |
| Prior version remains in an approved repository | Potentially possible | Reinstall the exact captured version, then verify dependent services. |
| Prior version was removed from approved repositories | Not possible | Stop rollout, preserve evidence, and require an operator-approved recovery plan. |
| Downgrade requires dependency removals | Denied | Do not pass `--allow-remove-essential` or accept removals; escalate for manual review. |
| Repository or signing-key change is required | Denied | Repository and key management remain outside the package action surface. |
| Database or file format migrated forward | Not safely automatic | Restore the separately captured application/data backup or follow the vendor procedure. |
| Package scripts made external changes | Not guaranteed | Inspect bounded logs and captured service/file state; do not claim full restoration. |
| Reboot completed into a new kernel | Not automatic | Select an already-installed approved kernel through a separate reviewed recovery procedure. |
| Package lock or interrupted package-manager state | Paused | Do not delete locks; require deterministic package-manager recovery and fresh preview. |

## Current enforced boundary

- Only opaque allowlisted package IDs and exact approved versions are accepted.
- The planner uses existing approved repositories and exposes no repository/key input.
- Preview rejects held packages and uses `apt-get --simulate --no-remove`.
- Canary rollout stops on removals, dependency surprises, version mismatch, or
  unhealthy dependent services.
- Recovery snapshots record the prior simulated version, but this is evidence—not
  proof that the version remains downloadable.
- The web API still exposes no live generic package-manager command.

## Release requirement

A disposable-lab release must demonstrate both a successful downgrade where the
captured version remains available and a fail-closed outcome where it does not.
The operator must sign off on the evidence and residual risk.
