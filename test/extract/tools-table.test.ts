import { describe, expect, it } from 'vitest'
import { KNOWN_TOOLS, type KnownToolSpec, lookupTool } from '../../src/extract/tools-table.js'
import { TierSchema } from '../../src/policy/decisions.js'

const FAMILIES: Record<string, KnownToolSpec['category'][]> = {
  'port scanners': ['port-scanner'],
  'web scanners/fuzzers': ['web-scanner', 'fuzzer'],
  'passive recon': ['passive-recon'],
  DNS: ['dns'],
  'HTTP clients': ['http-client'],
  'remote access': ['remote-access'],
  'SMB/AD': ['smb-ad'],
  'exploit frameworks': ['exploit-framework'],
  'brute-force': ['bruteforce'],
  DoS: ['dos'],
  'fetch/vcs/package managers': ['fetch', 'vcs', 'package-manager'],
  interpreters: ['interpreter'],
  listeners: ['listener'],
}

/** Every flag list of a spec and of its subcommands. */
function flagsOf(spec: Partial<KnownToolSpec>): string[] {
  const own = [
    ...(spec.hostFlags ?? []),
    ...(spec.urlFlags ?? []),
    ...(spec.fileFlags ?? []),
    ...(spec.excludeFlags ?? []),
    ...(spec.excludeFileFlags ?? []),
    ...(spec.valueFlags ?? []),
    ...(spec.nonNetworkFlags ?? []),
    ...(spec.credentialFlags ?? []),
    ...(spec.credentialHeaderFlags ?? []),
    ...(spec.urlOrFileFlags ?? []),
    ...(spec.infraFlags ?? []),
    ...(spec.nonTargetFlags ?? []),
    ...(spec.optionalValueFlags ?? []),
    ...(spec.bruteforceFileFlags ?? []),
    ...(spec.embeddedFlags ?? []).map((e) => e.flag),
    ...(spec.tierOverrides ?? []).map((o) => o.flag),
    ...(spec.hardDenyFlags ?? []).map((h) => h.flag),
    ...(spec.rateFlags ?? []).map((r) => r.flag),
  ]
  return [...own, ...Object.values(spec.subcommands ?? {}).flatMap(flagsOf)]
}

describe('KNOWN_TOOLS', () => {
  it('has at least 60 entries, each with names, a category and a tier', () => {
    expect(KNOWN_TOOLS.length).toBeGreaterThanOrEqual(60)
    for (const spec of KNOWN_TOOLS) {
      expect(spec.names.length, JSON.stringify(spec.names)).toBeGreaterThanOrEqual(1)
      expect(spec.category).toBeTruthy()
      expect(
        spec.tier === null || spec.tier === 'dos' || TierSchema.safeParse(spec.tier).success,
      ).toBe(true)
    }
  })

  it('never lists a name twice (case-insensitively)', () => {
    const seen = new Map<string, string>()
    for (const spec of KNOWN_TOOLS) {
      for (const name of spec.names) {
        const key = name.toLowerCase()
        expect(seen.has(key), `${name} also in ${seen.get(key)}`).toBe(false)
        seen.set(key, spec.names[0] ?? '')
      }
    }
  })

  it('covers every §6.4 family', () => {
    for (const [family, categories] of Object.entries(FAMILIES)) {
      const hit = KNOWN_TOOLS.some((s) => categories.includes(s.category))
      expect(hit, family).toBe(true)
    }
  })

  it('spells every flag as an option and marks network tools with help/version flags', () => {
    for (const spec of KNOWN_TOOLS) {
      for (const flag of flagsOf(spec)) expect(flag, spec.names[0]).toMatch(/^(?:--?|\/|\+)\S+$/)
    }
    expect(lookupTool('nmap')?.nonNetworkFlags).toEqual(expect.arrayContaining(['-V', '--version']))
    expect(lookupTool('curl')?.nonNetworkFlags).toEqual(expect.arrayContaining(['--version']))
  })

  it('declares the policy-relevant flags of the core tools', () => {
    const nmap = lookupTool('nmap')
    expect(nmap?.fileFlags).toContain('-iL')
    expect(nmap?.excludeFlags).toContain('--exclude')
    expect(nmap?.hardDenyFlags?.map((h) => h.flag)).toContain('-iR')
    expect(nmap?.rateFlags).toContainEqual({ flag: '-T', kind: 'nmap-timing' })
    expect(lookupTool('masscan')?.rateFlags).toContainEqual({ flag: '--rate', kind: 'pps' })
    expect(lookupTool('nuclei')?.rateFlags).toContainEqual({ flag: '-rl', kind: 'rps' })
    expect(lookupTool('ffuf')?.rateFlags).toContainEqual({ flag: '-t', kind: 'threads' })
    expect(lookupTool('git')?.subcommands?.clone?.tier).toBe('recon')
    expect(lookupTool('git')?.subcommands?.status).toBeUndefined()
  })
})

describe('lookupTool', () => {
  it('matches a basename and strips .exe', () => {
    expect(lookupTool('/usr/bin/nmap')?.names).toContain('nmap')
    expect(lookupTool('C:\\Tools\\nmap.exe')?.names).toContain('nmap')
    expect(lookupTool('grep')?.category).toBe('inert')
    expect(lookupTool('definitely-not-a-tool')).toBeUndefined()
  })

  it('is case-insensitive only on win32', () => {
    const hit = lookupTool('NMAP.EXE')
    if (process.platform === 'win32') expect(hit?.names).toContain('nmap')
    else expect(hit).toBeUndefined()
  })

  it('searches a custom table when given one', () => {
    const custom: KnownToolSpec[] = [{ names: ['zz'], category: 'fetch', tier: 'recon' }]
    expect(lookupTool('zz', custom)?.category).toBe('fetch')
    expect(lookupTool('nmap', custom)).toBeUndefined()
  })
})
