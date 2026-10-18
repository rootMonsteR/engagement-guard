import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  type CommandAnalysis,
  createTargetExtractor,
  type ExtractedTarget,
} from '../../src/extract/extractor.js'
import { formatRange } from '../../src/scope/ip.js'

const CWD = join(import.meta.dirname, '..', 'fixtures', 'commands', 'cwd')
const extractor = createTargetExtractor()
const analyze = (command: string, shell: 'posix' | 'powershell' = 'posix') =>
  extractor.analyze(command, { cwd: CWD, shell })
const raws = (a: CommandAnalysis) => a.targets.map((t) => t.raw).sort()
const byRaw = (a: CommandAnalysis, raw: string): ExtractedTarget | undefined =>
  a.targets.find((t) => t.raw === raw)

describe('extractor: brief cases', () => {
  it('nmap -iL reads each target line from the cwd file', async () => {
    const a = await analyze('nmap -iL targets-in.txt')
    expect(raws(a)).toEqual(
      [
        '192.0.2.10',
        '192.0.2.0/28',
        'www.acme.example',
        'https://portal.acme-partner.example:8443/app/login',
        '2001:db8:ac::10',
      ].sort(),
    )
    for (const t of a.targets) {
      expect(t.provenance).toBe('file')
      expect(t.source).toBe('targets-in.txt')
      expect(t.inert).toBe(false)
    }
    expect(a.knownNetwork).toBe(true)
    expect(a.tiers).toEqual(['recon'])
    expect(a.opaque).toEqual([])
  })

  it('nmap --exclude sets excludes and does not add the excluded host as a target', async () => {
    const a = await analyze('nmap 192.0.2.0/25 --exclude 192.0.2.66')
    expect(raws(a)).toEqual(['192.0.2.0/25'])
    expect(a.segments[0]?.excludes.map(formatRange)).toEqual(['192.0.2.66/32'])
    expect(byRaw(a, '192.0.2.0/25')?.provenance).toBe('positional')
  })

  it('--excludefile reads exclusions from the cwd', async () => {
    const a = await analyze('nmap --excludefile excludes.txt 192.0.2.0/25')
    expect(a.segments[0]?.excludes.map(formatRange)).toEqual([
      '192.0.2.66/32',
      '192.0.2.100-192.0.2.110',
    ])
  })

  it('nmap --version is non-network', async () => {
    const a = await analyze('nmap --version')
    expect(a.segments[0]?.nonNetwork).toBe(true)
    expect(a.knownNetwork).toBe(false)
    expect(a.tiers).toEqual([])
  })

  it('git status has no targets and is not network', async () => {
    const a = await analyze('git status')
    expect(a.targets).toEqual([])
    expect(a.knownNetwork).toBe(false)
    expect(a.segments[0]?.category).toBe('vcs')
  })

  it('git clone is a vcs network action with a positional URL', async () => {
    const a = await analyze('git clone https://github.com/x/y')
    expect(a.segments[0]?.category).toBe('vcs')
    expect(a.knownNetwork).toBe(true)
    expect(a.targets).toMatchObject([
      { raw: 'https://github.com/x/y', provenance: 'positional', inert: false },
    ])
  })
})

describe('extractor: segments, wrappers and provenance', () => {
  it('finds targets hidden behind chaining and wrappers', async () => {
    const a = await analyze(
      'ls && sudo -E env A=1 proxychains nmap -sV 203.0.113.5; time curl https://acme.example/x',
    )
    expect(raws(a)).toEqual(['203.0.113.5', 'https://acme.example/x'])
    expect(a.segments[1]).toMatchObject({
      program: 'nmap',
      wrappers: ['sudo', 'env', 'proxychains'],
    })
    expect(byRaw(a, '203.0.113.5')?.segment).toBe(1)
    expect(byRaw(a, 'https://acme.example/x')).toMatchObject({
      segment: 2,
      provenance: 'positional',
    })
  })

  it('records flag provenance with the flag as source', async () => {
    const a = await analyze('nuclei -u https://acme.example -rl 10')
    expect(a.targets).toMatchObject([
      { raw: 'https://acme.example', provenance: 'flag', source: '-u' },
    ])
  })

  it('marks literals in inert programs as inert', async () => {
    const a = await analyze('grep 203.0.113.5 auth.log')
    expect(a.targets).toMatchObject([{ raw: '203.0.113.5', provenance: 'literal', inert: true }])
    expect(a.knownNetwork).toBe(false)
  })

  it('keeps a non-inert occurrence over an inert one across segments', async () => {
    const a = await analyze('echo 192.0.2.10 | nmap 192.0.2.10')
    expect(a.targets).toMatchObject([{ raw: '192.0.2.10', provenance: 'positional', inert: false }])
  })

  it('unknown programs keep literal targets non-inert', async () => {
    const a = await analyze('./scan.sh 192.0.2.10')
    expect(a.targets).toMatchObject([{ raw: '192.0.2.10', provenance: 'literal', inert: false }])
    expect(a.knownNetwork).toBe(false)
  })

  it('does not take option values as positional targets', async () => {
    const a = await analyze('nmap -p 80,443 -oN scan.nmap -T3 --max-retries 2 192.0.2.10')
    expect(raws(a)).toEqual(['192.0.2.10'])
    expect(a.opaque).toEqual([])
  })

  it('handles clustered short flags for getopt tools', async () => {
    const a = await analyze('curl -sSLo out.html https://acme.example/')
    expect(raws(a)).toEqual(['https://acme.example/'])
    const nc = await analyze('nc -lvnp 4444')
    expect(nc.targets).toEqual([])
    expect(nc.segments[0]?.category).toBe('listener')
    expect(nc.knownNetwork).toBe(true)
  })

  it('takes only the destination of ssh, not the remote command', async () => {
    const a = await analyze('ssh -p 2222 -i key admin@192.0.2.10 ls -la /tmp')
    expect(a.targets).toMatchObject([{ raw: '192.0.2.10', provenance: 'positional' }])
    expect(a.opaque).toEqual([])
  })

  it('reads remote paths of scp and skips local ones', async () => {
    const a = await analyze('scp ./report.pdf ops@192.0.2.10:/tmp/')
    expect(raws(a)).toEqual(['192.0.2.10'])
    expect(a.opaque).toEqual([])
  })

  it('reads git remotes only from URL or scp-like positionals', async () => {
    const a = await analyze('git clone git@github.com:x/y.git mydir && git push origin main')
    expect(raws(a)).toEqual(['github.com'])
    expect(a.opaque).toEqual([])
  })

  it('parses UNC shares and dig servers', async () => {
    const smb = await analyze('smbclient //192.0.2.10/share -N')
    expect(raws(smb)).toEqual(['192.0.2.10'])
    const dig = await analyze('dig @1.1.1.1 acme.example MX +short')
    expect(raws(dig)).toEqual(['1.1.1.1', 'acme.example'])
    expect(dig.opaque).toEqual([])
  })

  it('treats package names as non-targets', async () => {
    const a = await analyze('pip install requests==2.31.0')
    expect(a.targets).toEqual([])
    expect(a.segments[0]?.category).toBe('package-manager')
    const npm = await analyze('npm test')
    expect(npm.knownNetwork).toBe(false)
  })
})

describe('extractor: tiers, credentials, hard deny and rate', () => {
  it('raises the tier from nmap --script categories', async () => {
    const vuln = await analyze('nmap --script vuln 192.0.2.10')
    expect(vuln.segments[0]).toMatchObject({ tier: 'vuln-scan', intrusive: true })
    const brute = await analyze('nmap --script=ssh-brute 192.0.2.10')
    expect(brute.tiers).toEqual(['bruteforce'])
    const safe = await analyze('nmap --script default 192.0.2.10')
    expect(safe.segments[0]).toMatchObject({ tier: 'recon', intrusive: false })
  })

  it('flags credentials from -u and Authorization headers', async () => {
    const u = await analyze('curl -u admin:pw https://acme.example')
    expect(u.segments[0]?.credentials).toBe(true)
    const h = await analyze('curl -H "Authorization: Bearer x" https://acme.example')
    expect(h.segments[0]?.credentials).toBe(true)
    const plain = await analyze('curl -H "Accept: */*" https://acme.example')
    expect(plain.segments[0]?.credentials).toBe(false)
  })

  it('reports hard-deny flags', async () => {
    const a = await analyze('nmap -iR 100 -p 80')
    expect(a.hardDeny).toMatch(/random/i)
    expect(a.segments[0]?.hardDeny).toBe(a.hardDeny)
  })

  it('collects rate flags', async () => {
    const a = await analyze('nmap -T4 --max-rate 5000 192.0.2.10')
    expect(a.segments[0]?.rate).toMatchObject({ nmapTiming: 4, pps: 5000 })
    const named = await analyze('nmap -T aggressive 192.0.2.10')
    expect(named.segments[0]?.rate.nmapTiming).toBe(4)
    const m = await analyze('masscan 192.0.2.0/25 -p80 --rate=100000')
    expect(m.segments[0]?.rate).toMatchObject({ pps: 100000, flags: { pps: '--rate' } })
    const f = await analyze('ffuf -u https://acme.example/FUZZ -w words.txt -t 200')
    expect(f.segments[0]?.rate.threads).toBe(200)
  })

  it('applies subcommand tiers (kerbrute passwordspray is bruteforce)', async () => {
    const a = await analyze(
      'kerbrute passwordspray -d acme.example --dc 192.0.2.10 users.txt Winter2026',
    )
    expect(a.tiers).toEqual(['bruteforce'])
    expect(raws(a)).toEqual(['192.0.2.10', 'acme.example'])
  })
})

describe('extractor: opaque constructs', () => {
  it('marks an unreadable target file', async () => {
    const a = await analyze('nmap -iL missing.txt')
    expect(a.opaque).toContain('unreadable-target-file')
    expect(a.targets).toEqual([])
  })

  it('refuses a target file written earlier in the same command', async () => {
    const a = await analyze('echo 203.0.113.5 > targets-in.txt && nmap -iL targets-in.txt')
    expect(a.opaque).toContain('unreadable-target-file')
    expect(a.targets.filter((t) => t.provenance === 'file')).toEqual([])
  })

  it('caps the target file size', async () => {
    const small = createTargetExtractor({ maxTargetFileBytes: 16 })
    const a = await small.analyze('nmap -iL targets-in.txt', { cwd: CWD, shell: 'posix' })
    expect(a.opaque).toContain('unreadable-target-file')
  })

  it('uses the injected readFile against the resolved path', async () => {
    const seen: string[] = []
    const custom = createTargetExtractor({
      readFile: async (p) => {
        seen.push(p)
        return '192.0.2.20\n# c\n\n203.0.113.9\n'
      },
    })
    const a = await custom.analyze('naabu -list hosts.lst', { cwd: CWD, shell: 'posix' })
    expect(seen).toEqual([join(CWD, 'hosts.lst')])
    expect(raws(a)).toEqual(['192.0.2.20', '203.0.113.9'])
  })

  it('marks out-of-file mixed lines too (no line is dropped)', async () => {
    const a = await analyze('httpx -l targets-mixed.txt')
    expect(raws(a)).toEqual(['192.0.2.10', '203.0.113.5', 'vpn.acme.example'])
  })

  it('marks unparseable targets in target positions', async () => {
    const a = await analyze('nmap http:8080')
    expect(a.opaque).toContain('unparseable-target')
    expect(a.segments[0]?.unparseable).toEqual(['http:8080'])
    const b = await analyze('curl -u x https://exa_mple')
    expect(b.segments[0]?.unparseable).toEqual(['https://exa_mple'])
  })

  it('parses a host/URL flag value even when it looks like a file name', async () => {
    const a = await analyze('nuclei -u portal.acme.json')
    expect(a.targets).toMatchObject([{ raw: 'portal.acme.json', provenance: 'flag' }])
  })

  it('keeps variables opaque and never parses them', async () => {
    const a = await analyze('nmap $TARGET')
    expect(a.opaque).toEqual(['variable'])
    expect(a.targets).toEqual([])
    expect(a.segments[0]?.unparseable).toEqual([])
  })

  it('flags eval and xargs and still sees the tool behind them', async () => {
    const e = await analyze('eval "nmap -iR 5"')
    expect(e.opaque).toContain('eval')
    expect(e.hardDeny).toMatch(/random/i)
    const x = await analyze('cat hosts | xargs -I{} nmap -T5 {}')
    expect(x.opaque).toContain('xargs')
    expect(x.knownNetwork).toBe(true)
    expect(x.segments[1]?.rate.nmapTiming).toBe(5)
  })

  it('analyses sh -c and python -m bodies', async () => {
    const a = await analyze("bash -lc 'nmap 203.0.113.5'")
    expect(raws(a)).toEqual(['203.0.113.5'])
    expect(a.knownNetwork).toBe(true)
    const p = await analyze('python3 -m pip install --index-url https://pypi.acme.example/simple x')
    expect(p.segments[0]?.category).toBe('package-manager')
    expect(raws(p)).toEqual(['https://pypi.acme.example/simple'])
  })

  it('flags substitution and keeps the known tool network-relevant', async () => {
    const a = await analyze('nmap $(cat hosts)')
    expect(a.opaque).toContain('command-substitution')
    expect(a.knownNetwork).toBe(true)
  })
})

describe('extractor: more forms', () => {
  it('reads -iL - from a stdin redirect and refuses a tee-written list', async () => {
    const a = await analyze('nmap -iL - < targets-mixed.txt')
    expect(raws(a)).toEqual(['192.0.2.10', '203.0.113.5', 'vpn.acme.example'])
    const bare = await analyze('cat x | nmap -iL -')
    expect(bare.opaque).toContain('unreadable-target-file')
    const tee = await analyze('echo 203.0.113.5 | tee targets-in.txt; nmap -iL targets-in.txt')
    expect(tee.opaque).toContain('unreadable-target-file')
  })

  it('keeps interpreter literals non-inert, including inside code strings', async () => {
    const a = await analyze(
      `python3 -c "import socket; socket.create_connection(('192.0.2.10', 80))"`,
    )
    expect(a.targets).toMatchObject([{ raw: '192.0.2.10', provenance: 'literal', inert: false }])
    expect(a.knownNetwork).toBe(false)
  })

  it('treats literals in non-network subcommands as inert', async () => {
    const a = await analyze('git commit -m "block 203.0.113.5"')
    expect(a.targets).toMatchObject([{ raw: '203.0.113.5', inert: true }])
  })

  it('analyses pwsh -Command as PowerShell', async () => {
    const a = await analyze('pwsh -NoProfile -Command Invoke-WebRequest https://acme.example')
    expect(a.opaque).toContain('powershell')
    expect(a.knownNetwork).toBe(true)
    expect(raws(a)).toEqual(['https://acme.example'])
  })

  it('reads impacket targets and their credentials', async () => {
    const a = await analyze('impacket-psexec acme/admin:Passw0rd@192.0.2.10 -dc-ip 192.0.2.5')
    expect(raws(a)).toEqual(['192.0.2.10', '192.0.2.5'])
    expect(a.segments[0]).toMatchObject({ credentials: true, tier: 'post-exploitation' })
  })

  it('reads xfreerdp /v: values and nxc protocol targets', async () => {
    const rdp = await analyze('xfreerdp /u:admin /v:192.0.2.10:3389')
    expect(rdp.targets).toMatchObject([
      { raw: '192.0.2.10:3389', provenance: 'flag', source: '/v' },
    ])
    const nxc = await analyze('nxc smb 192.0.2.0/28 -u admin -p pw -x whoami')
    expect(raws(nxc)).toEqual(['192.0.2.0/28'])
    expect(nxc.segments[0]).toMatchObject({ credentials: true, tier: 'post-exploitation' })
  })

  it('accepts a long decimal IPv4 positional but skips ports', async () => {
    const a = await analyze('nc -zv 3221225994 20-80')
    expect(a.targets).toMatchObject([{ raw: '3221225994', provenance: 'positional' }])
    expect(a.opaque).toEqual([])
  })
})

describe('extractor: powershell', () => {
  it('marks the whole command opaque and detects network cmdlets', async () => {
    const a = await analyze('Invoke-WebRequest -Uri https://acme.example/x', 'powershell')
    expect(a.shell).toBe('powershell')
    expect(a.opaque).toContain('powershell')
    expect(a.knownNetwork).toBe(true)
    expect(raws(a)).toEqual(['https://acme.example/x'])
  })

  it('detects aliases and network tools but not plain cmdlets', async () => {
    expect((await analyze('iwr acme.example', 'powershell')).knownNetwork).toBe(true)
    expect((await analyze('Get-ChildItem; nmap.exe 192.0.2.10', 'powershell')).knownNetwork).toBe(
      true,
    )
    const plain = await analyze('Get-ChildItem -Recurse', 'powershell')
    expect(plain.knownNetwork).toBe(false)
    expect(plain.opaque).toEqual(['powershell'])
  })
})

describe('extractor: robustness', () => {
  it('never throws on hostile input', async () => {
    const inputs = [
      '',
      'sudo',
      'xargs',
      'eval',
      'bash -c',
      'nmap -iL',
      'nmap -T',
      'curl -',
      'git',
      'nxc smb',
      'pwsh -c',
      'cmd /c',
      'python -m',
      'nmap --script=',
      '"unterminated',
      'eval eval eval eval eval eval nmap 192.0.2.10',
      'bash -c "bash -c \'bash -c \\"bash -c nmap\\"\'"',
      `nmap ${'a,'.repeat(2000)}`,
    ]
    for (const input of inputs) {
      await expect(analyze(input)).resolves.toBeDefined()
      await expect(analyze(input, 'powershell')).resolves.toBeDefined()
    }
  })
})
