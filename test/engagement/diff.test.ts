import { describe, expect, it } from 'vitest'
import { diffValues, renderDiff, scopeDiff } from '../../src/engagement/diff.js'

describe('diffValues', () => {
  it('is empty for equal values, whatever the key order', () => {
    expect(diffValues({ a: 1, b: [1, { c: 2, d: 3 }] }, { b: [1, { d: 3, c: 2 }], a: 1 })).toEqual(
      [],
    )
  })

  it('reports added, removed and changed keys by path', () => {
    const before = { roe: { rate_limits: { rps: 50 }, intrusive_checks: false }, gone: 'x' }
    const after = { roe: { rate_limits: { rps: 100 }, intrusive_checks: false, extra: true } }
    expect(diffValues(before, after)).toEqual([
      { op: 'removed', path: 'gone', value: 'x' },
      { op: 'added', path: 'roe.extra', value: true },
      { op: 'changed', path: 'roe.rate_limits.rps', before: 50, after: 100 },
    ])
  })

  it('aligns arrays so an insertion is one added entry, not a cascade of changes', () => {
    const before = { scope: { in: ['a.example', '192.0.2.0/25', 'b.example'] } }
    const after = { scope: { in: ['a.example', '203.0.113.0/24', '192.0.2.0/25', 'b.example'] } }
    expect(diffValues(before, after)).toEqual([
      { op: 'added', path: 'scope.in[1]', value: '203.0.113.0/24' },
    ])
  })

  it('reports removed array items at their old index and added ones at their new index', () => {
    expect(diffValues(['x', 'y', 'z'], ['x', 'z', 'w'])).toEqual([
      { op: 'removed', path: '[1]', value: 'y' },
      { op: 'added', path: '[2]', value: 'w' },
    ])
  })

  it('shows a changed object inside an array as removed + added', () => {
    const before = { blackout_hours: [{ start: '12:00', end: '13:00' }] }
    const after = { blackout_hours: [{ start: '12:00', end: '14:00' }] }
    expect(diffValues(before, after)).toEqual([
      { op: 'removed', path: 'blackout_hours[0]', value: { start: '12:00', end: '13:00' } },
      { op: 'added', path: 'blackout_hours[0]', value: { start: '12:00', end: '14:00' } },
    ])
  })

  it('reports a pure reordering', () => {
    const entries = diffValues({ in: ['a', 'b'] }, { in: ['b', 'a'] })
    expect(entries.length).toBeGreaterThan(0)
    expect(renderDiff(entries)).toContain('"a"')
  })

  it('reports a type change as changed', () => {
    expect(diffValues({ a: [1] }, { a: { x: 1 } })).toEqual([
      { op: 'changed', path: 'a', before: [1], after: { x: 1 } },
    ])
  })

  it('quotes keys that are not plain identifiers', () => {
    expect(diffValues({}, { 'a b': 1 })).toEqual([{ op: 'added', path: '["a b"]', value: 1 }])
  })

  it('handles long lists without quadratic blow-up', () => {
    const before = Array.from({ length: 5000 }, (_, i) => `h${i}.example`)
    const after = [...before.slice(0, 2500), 'new.example', ...before.slice(2500)]
    expect(diffValues(before, after)).toEqual([
      { op: 'added', path: '[2500]', value: 'new.example' },
    ])
  })
})

describe('renderDiff / scopeDiff', () => {
  it('renders one path line then -/+ value lines in compact JSON', () => {
    const text = scopeDiff(
      { scope: { in: ['192.0.2.0/25'] }, roe: { rate_limits: { rps: 50 } } },
      { scope: { in: ['192.0.2.0/25', '203.0.113.0/24'] }, roe: { rate_limits: { rps: 100 } } },
    )
    expect(text).toBe(
      ['roe.rate_limits.rps', '- 50', '+ 100', 'scope.in[1]', '+ "203.0.113.0/24"'].join('\n'),
    )
  })

  it('says so when nothing changed', () => {
    expect(scopeDiff({ a: 1 }, { a: 1 })).toBe('(no changes)')
  })
})
