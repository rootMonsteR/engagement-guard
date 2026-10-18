import { type CompiledList, compileList } from '../engagement/compile.js'
import type { ValidationIssue } from '../engagement/load.js'

/**
 * Infrastructure the operator relies on rather than tests (spec §10): code hosting, package
 * registries, distribution mirrors, container registries and public resolvers. Deliberately
 * conservative. Matching is by name or address only, never by DNS. Trusted infrastructure may be
 * fetched from, cloned or queried; it is never a scan, fuzz, exploit or brute-force target.
 */
export const DEFAULT_TRUSTED_INFRA: readonly string[] = Object.freeze([
  'github.com',
  '*.github.com',
  '*.githubusercontent.com',
  'ghcr.io',
  'registry.npmjs.org',
  'pypi.org',
  'files.pythonhosted.org',
  'crates.io',
  'static.crates.io',
  'proxy.golang.org',
  'sum.golang.org',
  'deb.debian.org',
  'security.debian.org',
  'http.kali.org',
  'archive.ubuntu.com',
  'security.ubuntu.com',
  'dl-cdn.alpinelinux.org',
  'registry-1.docker.io',
  'auth.docker.io',
  'production.cloudflare.docker.com',
  'gitlab.com',
  'bitbucket.org',
  'rubygems.org',
  'repo.maven.apache.org',
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '2606:4700:4700::1111',
  '2001:4860:4860::8888',
])

/**
 * Compiles a trusted-infrastructure list with the engagement entry rules; rule texts are
 * `trusted[<i>]: <entry>`. Throws when an entry does not compile: a list that silently drops
 * entries would hide a misconfiguration.
 */
export function compileTrustedInfra(
  entries: readonly string[] = DEFAULT_TRUSTED_INFRA,
): CompiledList {
  const issues: ValidationIssue[] = []
  const list = compileList('trusted', entries, issues)
  if (issues.length > 0) {
    const detail = issues.map((i) => `${i.path.replace(/^scope\./, '')}: ${i.message}`).join('; ')
    throw new Error(`invalid trusted infrastructure entry: ${detail}`)
  }
  return list
}
