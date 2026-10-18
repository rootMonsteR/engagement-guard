/**
 * The legal statements (spec §4.4), inlined so the package needs no data files. Each text is pinned
 * by its sha256 in `test/legal/statements.test.ts`: changing a wording means bumping its version,
 * which requires every operator to acknowledge again.
 */

/** The statement every operator acknowledges once per version before any network action. */
export const FIRST_RUN_V1: string = `# engagement-guard — operator acknowledgement (first-run-v1)

This tool stands between an AI agent and the security tools it runs. Before a network action
runs for you, the guard decides whether the active case authorises it, and it records the
decision. Before it decides anything, read this statement and confirm that you accept it. Your
acknowledgement is recorded on this machine with this statement's version, a SHA-256 of its text,
your operator name, the time and a host fingerprint. When the statement changes, you will be
asked again. You give it with: engagement-guard ack

## Your obligations

- You test only systems you are authorised in writing to test, only within the scope, the time
  window and the rules of engagement that authorisation sets out.
- You describe each engagement truthfully in .guard/engagement.yaml: who authorised it, what is
  in scope, what is out of scope, the window and the permitted test classes. This tool enforces
  that file; it cannot check that the file matches your contract. That is your responsibility.
- You attest each case before testing (engagement-guard engagement freeze) and attest every
  later change to its scope (engagement-guard engagement edit).
- You stop and report when you reach data or systems the authorisation does not cover.
- You comply with the law that applies to you, to your client and to the systems you test.
  This tool does not give legal advice and does not make an unauthorised test lawful.

## How enforcement works

- No case, no remote network action. Without an attested case, network actions are denied; only
  loopback targets and fetches from trusted infrastructure (package registries, source hosting,
  public resolvers) pass to the harness's ordinary permission rules.
- Every network action the agent proposes is checked by code, not by the model: targets are
  extracted from the command and compared with the case's in, out and operator lists, the time
  window, the blackout hours and the permitted test classes. Out-of-scope targets are denied;
  unknown or unreadable targets are put to you as a question.
- Denial-of-service testing is never permitted. Exploitation and post-exploitation require the
  rules of engagement to allow them and your explicit confirmation every time.
- The guard is only as present as the harness that calls it: a Claude Code PreToolUse hook that
  can deny or ask, a permission middleware in another harness, or the engagement-guard check
  command. Removing the hook or the middleware removes the enforcement for that session, and
  everything that session runs is then on you alone.
- While the guard is in place, nothing inside a session relaxes it: no flag, permission mode or
  answer to a prompt. Scope and window changes go through an audited
  engagement-guard engagement edit.
- Extraction is best effort. Commands built at run time (variables, substitutions, scripts,
  obfuscation) cannot always be read; this tool asks you instead of guessing. Treat it as a safety
  net, not as a substitute for your own judgement. A network-level egress control that does not
  depend on reading commands is the layer below it, and the configuration to rely on when
  compliance depends on it.

## What the audit log proves, and what it does not

- Every network decision, every answer you give and every command execution reported to the
  guard is written to an append-only, hash-chained log under .guard/audit/. Secrets in commands
  are redacted before a record is hashed and written. engagement-guard audit verify re-checks
  the chain and engagement-guard audit export produces a signed bundle you can hand to a client.
- The log shows that records were not altered, removed or reordered after the fact by someone
  without the signing key, and what this tool decided and saw during a session.
- It does not prove that you did not rewrite or delete the whole log yourself, that the machine
  clock was right, or that nothing ran outside this tool. It records what this tool saw; it is not
  evidence of authorisation. Keep your signed authorisation documents separately.

By acknowledging, you confirm that you have read this statement and accept these obligations.
`

/** The statement shown when a case is attested (`engagement-guard engagement freeze` / `edit`). */
export const ATTESTATION_V1: string = `# Case attestation (attestation-v1)

You are about to attest this case and freeze its scope. By attesting, you confirm that:

- You hold a written authorisation, identified in the case file, that covers every entry in
  \`scope.in\` and every host, network and URL the case lets this tool reach.
- The out-of-scope list, the time window, the time zone, the blackout hours and the rules of
  engagement in the case file match that authorisation.
- The test classes listed in \`roe.allowed_test_classes\` are permitted by it, and anything it
  prohibits is listed in \`roe.prohibited_actions\`.
- You will stop when the authorisation is withdrawn or the window ends, whatever the file says.

Freezing records your name, the time, this statement's version and a host fingerprint in the case
file, pins the scope with its \`scope_hash\`, keeps a snapshot of the frozen scope and writes an
audit record. Any later change to the type, profile, scope, rules of engagement, window or
execution settings unfreezes the case: network actions are denied until you review the change
and attest it again with \`engagement-guard engagement edit\`, which records the difference in the
audit log.
`

/** The statement texts by version. */
export const STATEMENTS: Readonly<Record<string, string>> = {
  'first-run-v1': FIRST_RUN_V1,
  'attestation-v1': ATTESTATION_V1,
}
