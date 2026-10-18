import { describe, expect, it } from 'vitest'
import type { SegmentAnalysis } from '../../src/extract/extractor.js'
import { ALWAYS_UNSKIPPABLE, effectiveTier, tierAllowed } from '../../src/policy/tiers.js'
import { analyze, roe } from './helpers.js'

const firstSegment = async (command: string): Promise<SegmentAnalysis> => {
  const a = await analyze(command)
  const seg = a.segments[0]
  if (!seg) throw new Error(`no segment for ${command}`)
  return seg
}

describe('effectiveTier', () => {
  it('nmap --script vuln without intrusive_checks escalates to exploitation', async () => {
    const seg = await firstSegment('nmap --script vuln 192.0.2.10')
    expect(effectiveTier(seg, roe({ intrusive_checks: false }))).toBe('exploitation')
  })

  it('nmap --script vuln with intrusive_checks keeps the vuln-scan tier', async () => {
    const seg = await firstSegment('nmap --script vuln 192.0.2.10')
    expect(effectiveTier(seg, roe({ intrusive_checks: true }))).toBe('vuln-scan')
  })

  it('curl -u admin:pw without credentialed_testing escalates to exploitation', async () => {
    const seg = await firstSegment('curl -u admin:pw https://acme.example')
    expect(effectiveTier(seg, roe({ credentialed_testing: false }))).toBe('exploitation')
  })

  it('curl -u admin:pw with credentialed_testing keeps the base tier', async () => {
    const seg = await firstSegment('curl -u admin:pw https://acme.example')
    expect(effectiveTier(seg, roe({ credentialed_testing: true }))).toBe('recon')
  })

  it('plain nmap is recon', async () => {
    expect(effectiveTier(await firstSegment('nmap -sV 192.0.2.10'), roe())).toBe('recon')
  })

  it('escalation never lowers a higher base tier', async () => {
    const seg = await firstSegment('nmap 192.0.2.10')
    const post: SegmentAnalysis = { ...seg, tier: 'post-exploitation', credentials: true }
    expect(effectiveTier(post, roe())).toBe('post-exploitation')
  })

  it('a bruteforce segment with credentials escalates to exploitation', async () => {
    const seg = await firstSegment('nmap 192.0.2.10')
    const brute: SegmentAnalysis = { ...seg, tier: 'bruteforce', credentials: true }
    expect(effectiveTier(brute, roe())).toBe('exploitation')
    expect(effectiveTier(brute, roe({ credentialed_testing: true }))).toBe('bruteforce')
  })

  it('a DoS tool is dos', async () => {
    expect(effectiveTier(await firstSegment('slowhttptest -u https://acme.example'), roe())).toBe(
      'dos',
    )
  })

  it('a recorded hard-deny flag is dos whatever the base tier', async () => {
    const seg = await firstSegment('nmap -iR 10')
    expect(seg.hardDeny).not.toBeNull()
    expect(effectiveTier(seg, roe())).toBe('dos')
  })

  it('non-network segments have no tier', async () => {
    expect(effectiveTier(await firstSegment('grep 192.0.2.10 notes.txt'), roe())).toBeNull()
    expect(effectiveTier(await firstSegment('nmap --version'), roe())).toBeNull()
    expect(effectiveTier(await firstSegment('mytool 192.0.2.10'), roe())).toBeNull()
  })
})

describe('tierAllowed', () => {
  it('consults roe.allowed_test_classes', () => {
    const r = roe({ allowed_test_classes: ['recon', 'exploitation'] })
    expect(tierAllowed('recon', r)).toBe(true)
    expect(tierAllowed('exploitation', r)).toBe(true)
    expect(tierAllowed('vuln-scan', r)).toBe(false)
    expect(tierAllowed('bruteforce', r)).toBe(false)
  })

  it('the default RoE allows recon and vuln-scan only', () => {
    const r = roe()
    expect(tierAllowed('recon', r)).toBe(true)
    expect(tierAllowed('vuln-scan', r)).toBe(true)
    expect(tierAllowed('exploitation', r)).toBe(false)
    expect(tierAllowed('post-exploitation', r)).toBe(false)
  })

  it('dos is never allowed', () => {
    const r = roe({
      allowed_test_classes: [
        'recon',
        'vuln-scan',
        'exploitation',
        'post-exploitation',
        'bruteforce',
      ],
    })
    expect(tierAllowed('dos', r)).toBe(false)
  })
})

describe('ALWAYS_UNSKIPPABLE', () => {
  it('holds exploitation and post-exploitation only', () => {
    expect([...ALWAYS_UNSKIPPABLE].sort()).toEqual(['exploitation', 'post-exploitation'])
  })
})
