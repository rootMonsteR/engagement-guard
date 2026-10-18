import { parseArgs } from 'node:util'
import {
  loadFirstRunAck,
  readFirstRunStatement,
  recordFirstRunAck,
  resolveOperator,
} from '../first-run.js'
import { resolvePaths } from '../paths.js'
import { readLine, refuseWithoutTerminal, writeLine } from './args.js'
import type { CliIo } from './main.js'

const USAGE = 'Usage: engagement-guard ack [--operator <name>]'

/**
 * Prints the first-run statement and records the operator's acknowledgement when they type
 * exactly `I AGREE`. Exit 0 recorded (or already recorded), 1 refused (also without a terminal).
 */
export async function runAck(args: string[], io: CliIo): Promise<number> {
  if (refuseWithoutTerminal(io, 'ack')) return 1
  let operator: string | undefined
  try {
    operator = parseArgs({
      args,
      options: { operator: { type: 'string' } },
      allowPositionals: false,
      strict: true,
    }).values.operator
  } catch (err) {
    writeLine(io.stderr, `${(err as Error).message}\n${USAGE}`)
    return 1
  }
  const home = resolvePaths({ env: io.env }).home
  const statement = await readFirstRunStatement()
  const existing = await loadFirstRunAck(home)
  if (existing !== undefined) {
    writeLine(
      io.stdout,
      `already acknowledged: ${existing.operator} at ${existing.at} (${statement.version})`,
    )
    return 0
  }
  io.stdout.write(`${statement.text}\nType I AGREE to acknowledge: `)
  const answer = await readLine(io.stdin)
  if (answer.trim() !== 'I AGREE') {
    io.stdout.write('\n')
    writeLine(io.stderr, 'not acknowledged: nothing recorded')
    return 1
  }
  const name = operator ?? resolveOperator(io.env)
  const now = io.now ?? (() => new Date())
  const ack = await recordFirstRunAck(home, name, now())
  io.stdout.write('\n')
  writeLine(
    io.stdout,
    `acknowledged: ${ack.operator} at ${ack.at} (${ack.statementVersion} ${ack.statementSha256.slice(0, 12)})`,
  )
  return 0
}
