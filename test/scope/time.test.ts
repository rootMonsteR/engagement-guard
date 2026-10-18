import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { type Engagement, EngagementSchema } from '../../src/engagement/schema.js'
import { checkTime } from '../../src/scope/time.js'

const FIXTURES = join(import.meta.dirname, '..', 'fixtures', 'engagements')

function acme(mutate?: (doc: Record<string, any>) => void): Engagement {
  const doc = parseYaml(readFileSync(join(FIXTURES, 'acme-external.yaml'), 'utf8'))
  mutate?.(doc)
  return EngagementSchema.parse(doc)
}

const at = (iso: string) => checkTime(acme(), new Date(iso))

describe('checkTime: window (Review Focus 7)', () => {
  it('is outside the window one second before it starts (06:00Z)', () => {
    expect(at('2026-10-20T05:59:59Z')).toMatchObject({ ok: false, reason: 'OUTSIDE_WINDOW' })
  })

  it('is inside the window at its first instant', () => {
    expect(at('2026-10-20T06:00:00Z')).toEqual({ ok: true })
  })

  it('treats the window end as exclusive', () => {
    expect(at('2026-10-31T16:59:59Z')).toEqual({ ok: true })
    expect(at('2026-10-31T17:00:00Z')).toMatchObject({ ok: false, reason: 'OUTSIDE_WINDOW' })
  })

  it('names the window in the message', () => {
    const r = at('2026-11-01T12:00:00Z')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.message).toContain('2026-10-31T18:00:00+01:00')
  })

  it('fails closed on an invalid clock', () => {
    expect(checkTime(acme(), new Date(Number.NaN))).toMatchObject({
      ok: false,
      reason: 'OUTSIDE_WINDOW',
    })
  })
})

describe('checkTime: blackout hours in the case time zone (Review Focus 7)', () => {
  it('blocks a weekday lunch hour (Wednesday 12:30 Amsterdam, CEST)', () => {
    const r = at('2026-10-21T10:30:00Z')
    expect(r).toMatchObject({ ok: false, reason: 'BLACKOUT' })
    if (!r.ok) expect(r.message).toContain('Europe/Amsterdam')
  })

  it('applies start inclusive, end exclusive', () => {
    expect(at('2026-10-21T10:00:00Z')).toMatchObject({ reason: 'BLACKOUT' })
    expect(at('2026-10-21T09:59:59Z')).toEqual({ ok: true })
    expect(at('2026-10-21T10:59:59Z')).toMatchObject({ reason: 'BLACKOUT' })
    expect(at('2026-10-21T11:00:00Z')).toEqual({ ok: true })
  })

  it('does not block Saturday 12:30 (the lunch entry is weekdays only)', () => {
    expect(at('2026-10-24T10:30:00Z')).toEqual({ ok: true })
  })

  it('blocks 00:30 Amsterdam on 2026-10-26, after DST ends, via the midnight-crossing entry', () => {
    expect(at('2026-10-25T23:30:00Z')).toMatchObject({ ok: false, reason: 'BLACKOUT' })
  })

  it('evaluates the midnight-crossing entry on both sides of midnight', () => {
    // CEST (+02:00) on 2026-10-22: 23:30 local is 21:30Z; 00:59 local on the 23rd is 22:59Z.
    expect(at('2026-10-22T21:29:59Z')).toEqual({ ok: true })
    expect(at('2026-10-22T21:30:00Z')).toMatchObject({ reason: 'BLACKOUT' })
    expect(at('2026-10-22T22:59:59Z')).toMatchObject({ reason: 'BLACKOUT' })
    expect(at('2026-10-22T23:00:00Z')).toEqual({ ok: true })
  })

  it('reads days[] of a midnight-crossing entry as the day the blackout starts', () => {
    const e = acme((d) => {
      d.roe.blackout_hours = [{ days: ['fri'], start: '22:00', end: '02:00' }]
    })
    // Friday 2026-10-23 23:00 CEST and Saturday 01:00 CEST are inside; Friday 01:00 is not.
    expect(checkTime(e, new Date('2026-10-23T21:00:00Z'))).toMatchObject({ reason: 'BLACKOUT' })
    expect(checkTime(e, new Date('2026-10-23T23:00:00Z'))).toMatchObject({ reason: 'BLACKOUT' })
    expect(checkTime(e, new Date('2026-10-22T23:00:00Z'))).toEqual({ ok: true })
    // Saturday 22:30 CEST is not a Friday start.
    expect(checkTime(e, new Date('2026-10-24T20:30:00Z'))).toEqual({ ok: true })
  })

  it('uses the wall clock of the case zone, not UTC or the host zone', () => {
    const e = acme((d) => {
      d.window.timezone = 'America/New_York'
      d.roe.blackout_hours = [{ start: '12:00', end: '13:00' }]
    })
    // 12:30 in New York (EDT, -04:00) on 2026-10-21 is 16:30Z.
    expect(checkTime(e, new Date('2026-10-21T16:30:00Z'))).toMatchObject({ reason: 'BLACKOUT' })
    expect(checkTime(e, new Date('2026-10-21T12:30:00Z'))).toEqual({ ok: true })
  })

  it('checks the window before blackout hours', () => {
    expect(at('2026-10-31T23:45:00Z')).toMatchObject({ reason: 'OUTSIDE_WINDOW' })
  })
})
