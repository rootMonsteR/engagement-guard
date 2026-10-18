#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { caseStatusLine, createGuard, type Guard } from 'engagement-guard'
import { z } from 'zod'
import { createExecEvents, guardedShell } from './guarded-shell.js'

export { createExecEvents, guardedShell } from './guarded-shell.js'

/**
 * An MCP server with two tools: `engagement_status` (the case status line) and `guarded_shell`
 * (a shell command that runs only when the guard passes it). Every decision and execution is in
 * the workspace's audit chain.
 */
export function createServer(guard: Guard): McpServer {
  const server = new McpServer({ name: 'engagement-guard-example', version: '0.1.0' })
  const events = createExecEvents(guard)

  server.registerTool(
    'engagement_status',
    { description: 'The status of the engagement case in this workspace', inputSchema: {} },
    async () => ({ content: [{ type: 'text', text: caseStatusLine(guard.cases.state()) }] }),
  )

  server.registerTool(
    'guarded_shell',
    {
      description:
        'Run a shell command in the workspace. It runs only if the engagement case authorises it; otherwise the decision is returned and nothing runs.',
      inputSchema: { command: z.string().min(1), cwd: z.string().optional() },
    },
    async ({ command, cwd }) => {
      const r = await guardedShell(
        guard,
        { command, ...(cwd === undefined ? {} : { cwd }) },
        events,
      )
      if (!r.ran) {
        return {
          isError: true,
          content: [
            { type: 'text', text: `${r.decision.verdict.toUpperCase()}: ${r.decision.message}` },
          ],
        }
      }
      const text = [`exit ${r.exitCode ?? 'null'}`, r.stdout, r.stderr && `stderr:\n${r.stderr}`]
        .filter((s) => s)
        .join('\n')
      return { content: [{ type: 'text', text }] }
    },
  )

  return server
}

export async function main(): Promise<void> {
  const guard = await createGuard({ cwd: process.cwd(), env: process.env, lock: true })
  const server = createServer(guard)
  const transport = new StdioServerTransport()
  const stop = async (): Promise<void> => {
    await server.close()
    await guard.dispose()
  }
  process.on('SIGINT', () => void stop().then(() => process.exit(0)))
  process.on('SIGTERM', () => void stop().then(() => process.exit(0)))
  await server.connect(transport)
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href
) {
  main().catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
