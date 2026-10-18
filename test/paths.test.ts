import { homedir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { resolvePaths } from '../src/paths.js'

describe('resolvePaths', () => {
  it('defaults to .guard under the workspace and ~/.engagement-guard', () => {
    const p = resolvePaths({ env: {} })
    expect(p).toMatchObject({
      dirName: '.guard',
      engagementPath: '.guard/engagement.yaml',
      auditDir: '.guard/audit',
      casesDir: '.guard/cases',
      commandHint: 'engagement-guard engagement edit',
    })
    expect(p.home).toBe(join(homedir(), '.engagement-guard'))
  })

  it('honours GUARD_HOME and a custom dirName', () => {
    const p = resolvePaths({ env: { GUARD_HOME: '/tmp/gh' }, dirName: '.case' })
    expect(p.home).toBe('/tmp/gh')
    expect(p.auditDir).toBe('.case/audit')
  })
})
