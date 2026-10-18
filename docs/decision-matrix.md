# Decision matrix

The two appendices of the Nemesis security plan this guard was extracted from, with names made product-neutral; `§` numbers refer to the Nemesis security spec.

## Appendix A — Decision matrix (spec §6.5, verbatim) and how the guard evaluates it

Applies to a network-class tool or a known network command:

| Situation | Decision |
|---|---|
| Denylist hit (DoS tools/flags, wiper/anti-forensics patterns, random/global targeting) | DENY `HARD_REFUSAL` |
| No active case · not acknowledged · tampered · outside window · blackout | DENY |
| Any target out-of-scope (explicit or via resolution) | DENY `OUT_OF_SCOPE` (message names the target + rule, offers `engagement-guard engagement edit`) |
| Any target unknown/unresolvable/range not fully authorised | ASK |
| Trusted infra (registries, GitHub, resolvers) with fetch/vcs/dns/remote-access | ALLOW → core rules |
| Trusted infra with scanner/fuzzer/exploit/bruteforce | DENY `INFRA_NOT_TARGET` |
| Tier not in RoE (`exploitation`, `post-exploitation`, `bruteforce`) | DENY `TIER_NOT_AUTHORISED` |
| Exploitation tier authorised | ASK **unskippable** |
| Rate/timing beyond RoE | DENY with compliant suggestion |
| Known network tool, no targets found · opaque construct · interpreter with in-scope literals | ASK |
| Unknown command, no targets | fall through to core permission rules |
| All in-scope, tier OK, rate OK | ALLOW → core rules |

How this plan reads the table:
1. The denylist is checked for every Bash command, network or not.
2. The case-state and time rows short-circuit, with two exceptions evaluated before them: all-loopback targets (§6.3, "core rules apply"), and the trusted-infra fetch/vcs/package/dns/remote-access row, so the coding agent (§2a domain 0) can still `git clone`/`npm install` with no case or outside the window. A trusted-infra host that the case lists in `in` or `out` is classified by the case instead.
3. Every other row is collected, deny rows outrank ask rows, and ask rows outrank allow. Within one verdict, table order picks the reason code.
4. "ALLOW → core rules" means `pass`, so core may still ask or deny. A guard ASK is never weakened by core (Global Constraints).
5. `operator-infra` targets behave like in-scope targets for every row.

## Appendix B — Reason codes (`REASON_CODES`, in this order)

| Code | Verdict | Meaning |
|---|---|---|
| `HARD_REFUSAL` | deny | denylist hit (§6.5, §6.11) |
| `FIRST_RUN_REQUIRED` | deny | no valid first-run acknowledgement |
| `NO_ACTIVE_CASE` | deny | no `.guard/engagement.yaml` |
| `CASE_INVALID` | deny | case file fails validation |
| `NOT_ACKNOWLEDGED` | deny | case not attested/frozen (§6.2) |
| `SCOPE_TAMPERED` | deny | frozen hash ≠ current `scope_hash` (§6.2) |
| `OUTSIDE_WINDOW` | deny | now ∉ [window.start, window.end) |
| `BLACKOUT` | deny | inside a blackout interval in the case timezone |
| `OUT_OF_SCOPE` | deny | target matches `out`, or a range intersects `out` |
| `RESOLVES_OUT_OF_SCOPE` | deny | a hostname resolves into `out` |
| `RESOLVES_PRIVATE` | deny | resolves to a private address on a non-internal case (§6.3) |
| `INFRA_NOT_TARGET` | deny | scanner/fuzzer/exploit/bruteforce against trusted infra |
| `TIER_NOT_AUTHORISED` | deny | tier (after intrusive/credentialed escalation) not in RoE |
| `RATE_EXCEEDS_ROE` | deny | timing/rate flag beyond `rate_limits`, with a suggestion |
| `AUDIT_UNAVAILABLE` | deny | audit log degraded; fail closed |
| `GUARD_ERROR` | deny | exception in the guard path; fail closed |
| `EXPLOITATION_CONFIRM` | ask-unskippable | exploitation/post-exploitation tier authorised by RoE |
| `UNKNOWN_TARGET` | ask | target matches no list |
| `UNRESOLVABLE` | ask | in-scope name failed to resolve |
| `THIRD_PARTY_HOSTING` | ask | resolved outside in-scope ranges with `require_ip_match` |
| `RANGE_NOT_FULLY_AUTHORISED` | ask | range only partly covered by `in` |
| `NO_TARGETS_FOUND` | ask | known network tool, no target extracted |
| `OPAQUE_CONSTRUCT` | ask | substitution/eval/xargs/variable/unbalanced quote/unreadable target file |
| `INTERPRETER_TARGETS` | ask | interpreter or unknown program with in-scope literals |
| `POWERSHELL_NETWORK_TOOL` | ask | PowerShell command naming a network tool (§10) |
| `IN_SCOPE` | pass | all targets in scope; tier and rate OK |
| `OPERATOR_INFRA` | pass | all remaining targets are operator infrastructure |
| `TRUSTED_INFRA` | pass | trusted infra with fetch/vcs/package/dns/remote-access |
| `LOCAL_TARGET` | pass | loopback only |
| `NOT_NETWORK` | pass | not a network action; core rules decide |

## Against the code

Every code above is in `REASON_CODES` (`src/policy/decisions.ts`). The code has one more, which this appendix predates:

| Code | Verdict | Meaning |
|---|---|---|
| `PROTECTED_PATH` | deny | a command or a `Write`/`Edit` call would write, move, remove or link the case file, the frozen scope snapshots, the audit log, or the home's acknowledgement and keys (Nemesis ruling P24; `src/policy/protected-paths.ts`) |

In `REASON_CODES` it sits second, after `HARD_REFUSAL`. Within one verdict the guard picks the code that comes first in `REASON_CODES` (`src/policy/guard.ts`), so that order is part of the behaviour.
