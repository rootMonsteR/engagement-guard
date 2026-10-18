/**
 * Shell operators that chain or substitute another command: `;` `&&` `||` `|` newline, backtick,
 * command substitution `$(`, process substitution `<(` `>(`, and a single `&` — except the `&`
 * of a redirection (`2>&1`, `>&2`, `<&0`, `&>file`).
 */
const CHAIN_SOURCE = String.raw`&&|\|\||[;|\n\r\`]|[$<>]\(|(?<![<>&])&(?![>&])`
export const SHELL_CHAIN = new RegExp(CHAIN_SOURCE)
const SHELL_CHAIN_ALL = new RegExp(CHAIN_SOURCE, 'g')

/**
 * A command split on the chaining operators. `segments` are the raw (untrimmed) texts between
 * operators, so `segments.length === operators.length + 1`; `operators[i]` sits between
 * `segments[i]` and `segments[i + 1]`.
 */
export interface ShellChain {
  segments: string[]
  operators: string[]
}

/**
 * Splits `command` on the operators of `CHAIN_SOURCE` (`;` `&&` `||` `|` newline, CR, backtick,
 * `$(` `<(` `>(` and a lone `&`, but not a redirection's `&`). This is the segmentation the
 * deny-side prefix matcher uses. It is lexical: quotes and escapes are not interpreted, so a
 * quoted operator still splits (fail-closed for deny).
 */
export function splitShellChain(command: string): ShellChain {
  const segments: string[] = []
  const operators: string[] = []
  let last = 0
  for (const m of command.matchAll(SHELL_CHAIN_ALL)) {
    segments.push(command.slice(last, m.index))
    operators.push(m[0])
    last = m.index + m[0].length
  }
  segments.push(command.slice(last))
  return { segments, operators }
}
