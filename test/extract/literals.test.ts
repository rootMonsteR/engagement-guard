import { describe, expect, it } from 'vitest'
import { sweepLiterals } from '../../src/extract/literals.js'

const raws = (argv: string[]) => sweepLiterals(argv).map((l) => l.raw)

describe('sweepLiterals: catches', () => {
  it('IPv4, CIDR, IPv6, URLs and user@host', () => {
    expect(raws(['x', '192.0.2.10'])).toEqual(['192.0.2.10'])
    expect(raws(['192.0.2.0/24'])).toEqual(['192.0.2.0/24'])
    expect(raws(['[2001:db8::1]:80'])).toEqual(['[2001:db8::1]:80'])
    expect(raws(['2001:db8::1'])).toEqual(['2001:db8::1'])
    expect(raws(['https://acme.example/x'])).toEqual(['https://acme.example/x'])
    expect(raws(['user@host.acme.example'])).toEqual(['host.acme.example'])
  })

  it('targets inside k=v, --opt=v, scp and socat forms', () => {
    expect(raws(['RHOSTS=192.0.2.10'])).toEqual(['192.0.2.10'])
    expect(raws(['--url=https://acme.example/'])).toEqual(['https://acme.example/'])
    expect(raws(['git@github.example:x/y.git'])).toEqual(['github.example'])
    expect(raws(['TCP-CONNECT:192.0.2.5:80'])).toEqual(['192.0.2.5:80'])
    expect(raws(['@1.1.1.1'])).toEqual(['1.1.1.1'])
    expect(raws(['acme.example:8443'])).toEqual(['acme.example:8443'])
    expect(raws(['192.0.2.10,192.0.2.11'])).toEqual(['192.0.2.10', '192.0.2.11'])
    expect(raws(['acme.example/admin'])).toEqual(['acme.example/admin'])
    expect(raws(['//192.0.2.10/share'])).toEqual(['192.0.2.10'])
    expect(raws(['(see', 'www.acme.example).'])).toEqual(['www.acme.example'])
  })

  it('returns parsed targets and dedupes by raw', () => {
    const hits = sweepLiterals(['https://acme.example/x', 'https://acme.example/x'])
    expect(hits).toHaveLength(1)
    expect(hits[0]?.target).toMatchObject({ kind: 'url', host: 'acme.example', port: 443 })
  })
})

describe('sweepLiterals: ignores', () => {
  it('versions, file names, OIDs, semver and option names', () => {
    expect(raws(['requests==2.31.0', 'pkg>=1.2.3.4'])).toEqual([])
    expect(raws(['lodash@4.17.21', '@types/node@20.1.0'])).toEqual([])
    expect(raws(['report.json', 'scan.nmap', 'README.md'])).toEqual([])
    expect(raws(['1.3.6.1.4.1'])).toEqual([])
    expect(raws(['1.2.3', 'v1.2.3'])).toEqual([])
    expect(raws(['--top-ports', '-sV'])).toEqual([])
  })

  it('variables, plain words, ports and times', () => {
    expect(raws(['$HOST', '${T}.acme.example'])).toEqual([])
    expect(raws(['hello', '80', '10:30', '12:30:45', 'C:\\temp\\x', 'file:///etc/hosts'])).toEqual(
      [],
    )
  })
})
