# Phase 22 Security Validation

Status: in progress. Scope: simulation and application-policy boundary only.

## Automated evidence

| Scenario | Expected result | Evidence |
| --- | --- | --- |
| Prompt injection embedded in managed content | Remains bounded diff data; never becomes an argument or instruction | `test_prompt_injection_content_remains_bounded_data` |
| Approval replay after plan revision | Original token is invalidated | `test_approval_replay_cross_session_and_stale_plan_are_denied` |
| Cross-session approval use | Transaction ownership check denies access | `test_approval_replay_cross_session_and_stale_plan_are_denied` |
| Backend restart after Backup | Authority resets to Observe and advancement fails until explicitly rearmed | `test_restart_mid_workflow_fails_closed_until_authority_is_rearmed` |
| Overlapping or crashed host lock | Live lock blocks; expired lock is reclaimed | `test_expired_lock_is_recovered_but_live_lock_blocks` |
| Production host in Autonomous Lab | Server-side environment policy denies arming | `test_production_host_cannot_enter_autonomous_mode` |
| Restart after each persisted workflow stage | Advancement fails closed; explicit rearm permits verified, idempotent rollback | `test_recovery_drill_after_every_persisted_stage` |
| Cross-user access with a known session ID | Transaction ownership check denies access | `test_cross_user_transaction_access_is_denied_even_with_session_id` |
| Rollback attempted without active authority | Denied and recorded as `change_rollback_denied` | `test_rollback_authority_denial_is_audited` |

## Residual validation work

- Exercise symlink swaps against a deployed host-side file helper.
- Kill the process during real backup, apply, activation, verification, and rollback.
- Validate production classification at transport identity and deployed helper layers.
- Run recovery drills on disposable lab VMs and record named operator sign-off.
- Document package operations that cannot be rolled back because an approved prior version is unavailable.

The simulation recovery drill is documented in `docs/PHASE22_RECOVERY_DRILL.md`.
Package-specific non-rollbackable cases and release requirements are documented
in `docs/PACKAGE_ROLLBACK_LIMITATIONS.md`.

No result in this report authorizes release to a real host. Phase 22 remains open
until deployed helper, crash-recovery, and operator-sign-off evidence is complete.
