import { mkdir, readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { AuditRecordSchema } from '../../src/audit/record.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { hookOutput, hookRequest, parseHookInput } from '../../src/cli/hook.js'
import { runCli } from '../../src/cli/main.js'
import { type ActiveCase, activeCase } from '../helpers/case-fixture.js'
import { createCliIo, type TestCliIo } from '../helpers/cli-io.js'

const SESSION = 'a1b2c3d4-0000-4000-8000-000000000001'

interface HookJson {
  hookSpecificOutput: {
    hookEventName: string
    permissionDecision: string
    permissionDecisionReason: string
  }
}

function hookStdin(
  cwd: string,
  command: string,
  over: { tool_name?: string; session_id?: string; tool_input?: Record<string, unknown> } = {},
): string {
  return JSON.stringify({
    session_id: over.session_id ?? SESSION,
    transcript_path: '/tmp/transcript.jsonl',
    cwd,
    hook_event_name: 'PreToolUse',
    tool_name: over.tool_name ?? 'Bash',
    tool_input: over.tool_input ?? { command, description: 'test' },
    tool_use_id: 'toolu_hook_1',
  })
}

function decision(io: TestCliIo): HookJson['hookSpecificOutput'] {
  return (JSON.parse(io.out()) as HookJson).hookSpecificOutput
}

describe('engagement-guard hook on an active case', () => {
  let c: ActiveCase

  beforeEach(async () => {
    c = await activeCase()
  })

  afterEach(async () => {
    await c.cleanup()
  })

  const io = (stdin: string): TestCliIo =>
    createCliIo({
      cwd: c.cwd,
      env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
      now: c.now,
      lookup: c.lookup,
      stdin,
    })

  it('denies an out-of-scope Bash command', async () => {
    const o = io(hookStdin(c.cwd, 'nmap 203.0.113.5'))
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.hookEventName).toBe('PreToolUse')
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason).toContain('OUT_OF_SCOPE')
    expect(d.permissionDecisionReason).toContain('203.0.113.5')
  })

  it('asks for a partly authorised range', async () => {
    const o = io(hookStdin(c.cwd, 'nmap 192.0.2.120-140'))
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('ask')
    expect(d.permissionDecisionReason).toContain('RANGE_NOT_FULLY_AUTHORISED')
    expect(d.permissionDecisionReason.startsWith('[cannot be auto-approved]')).toBe(false)
  })

  it('stays silent on a pass', async () => {
    const o = io(hookStdin(c.cwd, 'nmap 192.0.2.10'))
    expect(await runCli(['hook'], o)).toBe(0)
    expect(o.out()).toBe('')
    expect(o.err()).toBe('')
  })

  it('ignores other tools', async () => {
    const o = io(hookStdin(c.cwd, 'nmap 203.0.113.5', { tool_name: 'Read' }))
    expect(await runCli(['hook'], o)).toBe(0)
    expect(o.out()).toBe('')
  })

  it('inspects an extra tool named with --tool', async () => {
    const o = io(hookStdin(c.cwd, 'nmap 203.0.113.5', { tool_name: 'Shell' }))
    expect(await runCli(['hook', '--tool', 'Shell'], o)).toBe(0)
    expect(decision(o).permissionDecision).toBe('deny')
  })

  it('inspects the whole input of a non-shell tool named with --tool', async () => {
    const o = io(
      hookStdin(c.cwd, '', { tool_name: 'WebFetch', tool_input: { url: 'http://203.0.113.5/' } }),
    )
    expect(await runCli(['hook', '--tool', 'WebFetch'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason).toContain('OUT_OF_SCOPE')
  })

  const fileTool = (tool: string, input: Record<string, unknown>): string =>
    hookStdin(c.cwd, '', { tool_name: tool, tool_input: input })

  it('denies a Write to the case file by default', async () => {
    const file = join(c.cwd, '.guard', 'engagement.yaml')
    const o = io(fileTool('Write', { file_path: file, content: 'scope: everything' }))
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason).toContain('PROTECTED_PATH')
  })

  it('denies a Write to the case file named relative to the hook cwd', async () => {
    const o = io(fileTool('Write', { file_path: '.guard/engagement.yaml', content: 'x' }))
    expect(await runCli(['hook'], o)).toBe(0)
    expect(decision(o).permissionDecision).toBe('deny')
    expect(decision(o).permissionDecisionReason).toContain('PROTECTED_PATH')
  })

  it('denies an Edit of the case file by default', async () => {
    const file = join(c.cwd, '.guard', 'engagement.yaml')
    const o = io(fileTool('Edit', { file_path: file, old_string: 'a', new_string: 'b' }))
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason).toContain('PROTECTED_PATH')
  })

  it('denies a MultiEdit of the case file by default', async () => {
    const file = join(c.cwd, '.guard', 'engagement.yaml')
    const o = io(
      fileTool('MultiEdit', { file_path: file, edits: [{ old_string: 'a', new_string: 'b' }] }),
    )
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason).toContain('PROTECTED_PATH')
  })

  it('denies a NotebookEdit under .guard/audit by default', async () => {
    const nb = join(c.cwd, '.guard', 'audit', 'x.ipynb')
    const o = io(fileTool('NotebookEdit', { notebook_path: nb, new_source: 'print(1)' }))
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason).toContain('PROTECTED_PATH')
  })

  it('stays silent on a Write outside the protected paths', async () => {
    const o = io(fileTool('Write', { file_path: join(c.cwd, 'src', 'x.ts'), content: 'x' }))
    expect(await runCli(['hook'], o)).toBe(0)
    expect(o.out()).toBe('')
    expect(o.err()).toBe('')
  })

  it('denies GUARD_ERROR for a file tool whose payload has no path', async () => {
    const o = io(fileTool('Write', { content: 'x' }))
    expect(await runCli(['hook'], o)).toBe(2)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason.startsWith('GUARD_ERROR:')).toBe(true)
    expect(o.err()).toContain('GUARD_ERROR:')
  })

  it('denies GUARD_ERROR for a Bash payload without a command', async () => {
    const o = io(hookStdin(c.cwd, '', { tool_input: { description: 'x' } }))
    expect(await runCli(['hook'], o)).toBe(2)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason.startsWith('GUARD_ERROR:')).toBe(true)
    expect(o.err()).toContain('GUARD_ERROR:')
  })

  it('denies GUARD_ERROR when the decision outlives --timeout-ms', async () => {
    const o = createCliIo({
      cwd: c.cwd,
      env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
      now: c.now,
      lookup: () => new Promise(() => {}),
      stdin: hookStdin(c.cwd, 'nmap www.acme.example'),
    })
    const started = Date.now()
    expect(await runCli(['hook', '--timeout-ms', '300'], o)).toBe(2)
    expect(Date.now() - started).toBeLessThan(1500)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason.startsWith('GUARD_ERROR:')).toBe(true)
    expect(d.permissionDecisionReason).toContain('timed out')
    expect(o.err()).toContain('timed out')
  })

  it('denies GUARD_ERROR on a --timeout-ms that is not a positive integer', async () => {
    for (const bad of ['0', '-5', 'soon', '1.5']) {
      const o = io(hookStdin(c.cwd, 'nmap 192.0.2.10'))
      expect(await runCli(['hook', '--timeout-ms', bad], o)).toBe(2)
      expect(decision(o).permissionDecisionReason).toContain('--timeout-ms')
    }
  })

  it('denies GUARD_ERROR on malformed stdin', async () => {
    const o = io('not json')
    expect(await runCli(['hook'], o)).toBe(2)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason.startsWith('GUARD_ERROR:')).toBe(true)
    expect(o.err()).toContain('GUARD_ERROR:')
  })

  it('denies GUARD_ERROR when the guard cannot start', async () => {
    const o = io(hookStdin(c.cwd, 'nmap 192.0.2.10', { session_id: 'bad session id!' }))
    expect(await runCli(['hook'], o)).toBe(2)
    const d = decision(o)
    expect(d.permissionDecision).toBe('deny')
    expect(d.permissionDecisionReason.startsWith('GUARD_ERROR:')).toBe(true)
    expect(o.err()).toContain('GUARD_ERROR:')
  })

  it.runIf(process.platform === 'win32')('decides the same with a Windows cwd', async () => {
    expect(c.cwd).toMatch(/^[A-Za-z]:\\/)
    const o = io(hookStdin(c.cwd, 'nmap 203.0.113.5'))
    expect(await runCli(['hook'], o)).toBe(0)
    expect(decision(o).permissionDecision).toBe('deny')
    expect((await verifyAudit(join(c.cwd, '.guard', 'audit'))).ok).toBe(true)
  })

  it('resolves the case from CLAUDE_PROJECT_DIR when the hook cwd is a subdirectory', async () => {
    const sub = join(c.cwd, 'src')
    await mkdir(sub)
    const o = createCliIo({
      cwd: sub,
      env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice', CLAUDE_PROJECT_DIR: c.cwd },
      now: c.now,
      lookup: c.lookup,
      stdin: hookStdin(sub, 'nmap 203.0.113.5'),
    })
    expect(await runCli(['hook'], o)).toBe(0)
    expect(decision(o).permissionDecision).toBe('deny')
    expect(decision(o).permissionDecisionReason).toContain('OUT_OF_SCOPE')
    expect((await verifyAudit(join(c.cwd, '.guard', 'audit'))).ok).toBe(true)
  })

  it('stays silent on an event that is not PreToolUse', async () => {
    const payload = JSON.parse(hookStdin(c.cwd, 'nmap 203.0.113.5')) as Record<string, unknown>
    payload.hook_event_name = 'PostToolUse'
    const o = io(JSON.stringify(payload))
    expect(await runCli(['hook'], o)).toBe(0)
    expect(o.out()).toBe('')
  })

  it('writes the decision to the audit chain under the workspace', async () => {
    await runCli(['hook'], io(hookStdin(c.cwd, 'nmap 203.0.113.5')))
    const dir = join(c.cwd, '.guard', 'audit')
    expect((await verifyAudit(dir)).ok).toBe(true)
    const text = await readFile(join(dir, c.caseId, `${SESSION}.jsonl`), 'utf8')
    const kinds = text
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => AuditRecordSchema.parse(JSON.parse(l)).kind)
    expect(kinds).toContain('decision')
  })
})

describe('engagement-guard hook on an exploit case', () => {
  let c: ActiveCase

  beforeEach(async () => {
    c = await activeCase({ which: 'exploit' })
  })

  afterEach(async () => {
    await c.cleanup()
  })

  it('prefixes an unskippable ask', async () => {
    const o = createCliIo({
      cwd: c.cwd,
      env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
      now: c.now,
      lookup: c.lookup,
      stdin: hookStdin(c.cwd, 'evil-winrm -i 192.0.2.10 -u admin -p pw'),
    })
    expect(await runCli(['hook'], o)).toBe(0)
    const d = decision(o)
    expect(d.permissionDecision).toBe('ask')
    expect(d.permissionDecisionReason.startsWith('[cannot be auto-approved] ')).toBe(true)
    expect(d.permissionDecisionReason).toContain('EXPLOITATION_CONFIRM')
  })
})

describe('hook helpers', () => {
  it('parseHookInput reads the Claude Code fields and rejects anything else', () => {
    expect(parseHookInput(hookStdin('/w', 'ls'))).toEqual({
      toolName: 'Bash',
      command: 'ls',
      input: { command: 'ls', description: 'test' },
      cwd: '/w',
      sessionId: SESSION,
      toolUseId: 'toolu_hook_1',
      event: 'PreToolUse',
    })
    expect(parseHookInput('{}')).toMatchObject({ error: expect.any(String) })
    expect(parseHookInput('[1')).toMatchObject({ error: expect.any(String) })
  })

  it('parseHookInput leaves command out when the payload has none', () => {
    const parsed = parseHookInput(hookStdin('/w', '', { tool_input: { description: 'x' } }))
    expect(parsed).not.toHaveProperty('command')
  })

  it('hookRequest makes each file tool a write-class request for its path under cwd', () => {
    const cwd = resolve('/w')
    const at = (tool: string, input: Record<string, unknown>) => {
      const parsed = parseHookInput(hookStdin(cwd, '', { tool_name: tool, tool_input: input }))
      if ('error' in parsed) throw new Error(parsed.error)
      return hookRequest(parsed)
    }
    const file = join(cwd, '.guard', 'engagement.yaml')
    for (const tool of ['Write', 'Edit', 'MultiEdit']) {
      const input = { file_path: '.guard/engagement.yaml' }
      expect(at(tool, input)).toMatchObject({
        toolName: tool,
        permissionClass: 'write',
        ruleKey: file,
        summary: `${tool} ${file}`,
        input,
        cwd,
      })
    }
    const nb = join(cwd, '.guard', 'audit', 'x.ipynb')
    expect(at('NotebookEdit', { notebook_path: nb })).toMatchObject({
      toolName: 'NotebookEdit',
      permissionClass: 'write',
      ruleKey: nb,
      summary: `NotebookEdit ${nb}`,
    })
    expect(at('NotebookEdit', { file_path: nb })).toMatchObject({ error: expect.any(String) })
    expect(at('Write', { file_path: 7 })).toMatchObject({ error: expect.any(String) })
    expect(at('Bash', { description: 'x' })).toMatchObject({ error: expect.any(String) })
    expect(at('WebFetch', { url: 'http://x/' })).toMatchObject({
      permissionClass: 'network',
      ruleKey: 'WebFetch',
      summary: 'WebFetch',
    })
  })

  it('hookOutput is silent for pass and not-inspected', () => {
    expect(hookOutput('not-inspected')).toBeUndefined()
  })
})
