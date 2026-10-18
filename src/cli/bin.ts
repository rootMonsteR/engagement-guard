#!/usr/bin/env node
import { runCli } from './main.js'

const code = await runCli(process.argv.slice(2), {
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  cwd: process.cwd(),
  env: process.env,
  tty: process.stdin.isTTY === true && process.stdout.isTTY === true,
})

// Drain both streams, then exit. A hook whose decision timed out (deny printed) must not be kept
// alive by lookups still in flight: the harness would count the hook as timed out and run the call.
await new Promise<void>((resolve) => process.stdout.write('', () => resolve()))
await new Promise<void>((resolve) => process.stderr.write('', () => resolve()))
process.exit(code)
