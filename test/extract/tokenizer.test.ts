import { describe, expect, it } from 'vitest'
import { stripWrappers, tokenizeCommand, WRAPPERS } from '../../src/extract/tokenizer.js'

const argvOf = (command: string) => tokenizeCommand(command).map((s) => s.argv)
const opaqueOf = (command: string) => tokenizeCommand(command).map((s) => s.opaque)

describe('tokenizeCommand: words', () => {
  it('keeps a double-quoted string as one word', () => {
    expect(argvOf('curl "a b"')).toEqual([['curl', 'a b']])
  })

  it('handles single quotes, escaped quotes and backslash-escaped blanks', () => {
    expect(argvOf(`echo 'x y' "a\\"b" c\\ d 'it''s'`)).toEqual([
      ['echo', 'x y', 'a"b', 'c d', 'its'],
    ])
  })

  it('keeps a backslash literally inside single quotes', () => {
    expect(argvOf(String.raw`printf '\n' "\q"`)).toEqual([
      ['printf', String.raw`\n`, String.raw`\q`],
    ])
  })

  it('drops redirections and records their targets', () => {
    const [seg] = tokenizeCommand('nmap 192.0.2.10 -oN x >out.txt 2>&1 >> log.txt < in.txt &>all')
    expect(seg?.argv).toEqual(['nmap', '192.0.2.10', '-oN', 'x'])
    expect(seg?.redirects).toEqual([
      { op: '>', target: 'out.txt' },
      { op: '>&', target: '1', fd: '2' },
      { op: '>>', target: 'log.txt' },
      { op: '<', target: 'in.txt' },
      { op: '&>', target: 'all' },
    ])
  })

  it('ignores comments and subshell parentheses', () => {
    expect(argvOf('(nmap 192.0.2.10) # 203.0.113.5')).toEqual([['nmap', '192.0.2.10']])
  })

  it('joins backslash-newline continuations', () => {
    expect(argvOf('nmap \\\n  192.0.2.10')).toEqual([['nmap', '192.0.2.10']])
  })

  it('splits on core chain operators and records operatorBefore', () => {
    const segs = tokenizeCommand('a 1 && b 2 | c; d')
    expect(segs.map((s) => [s.index, s.argv, s.operatorBefore])).toEqual([
      [0, ['a', '1'], null],
      [1, ['b', '2'], '&&'],
      [2, ['c'], '|'],
      [3, ['d'], ';'],
    ])
  })
})

describe('tokenizeCommand: opaque constructs', () => {
  it('flags an unbalanced quote', () => {
    expect(opaqueOf('curl "http://acme.example')[0]).toContain('unbalanced-quote')
    expect(opaqueOf("nmap '192.0.2.10")[0]).toContain('unbalanced-quote')
  })

  it('flags command substitution on the segment it opens and on the parent', () => {
    const segs = tokenizeCommand('nmap $(cat hosts)')
    expect(segs).toHaveLength(2)
    expect(segs[0]?.opaque).toContain('command-substitution')
    expect(segs[1]?.opaque).toContain('command-substitution')
    expect(segs[1]?.operatorBefore).toBe('$(')
  })

  it('flags backticks', () => {
    const segs = tokenizeCommand('nmap `cat hosts` -p 80')
    expect(segs.every((s) => s.opaque.includes('backticks'))).toBe(true)
  })

  it('flags process substitution', () => {
    expect(opaqueOf('diff <(nmap a) b')[0]).toContain('process-substitution')
  })

  it('flags variables, braces and positional parameters but not single-quoted dollars', () => {
    expect(opaqueOf('nmap $T')[0]).toContain('variable')
    expect(opaqueOf('nmap "${HOST}"')[0]).toContain('variable')
    expect(opaqueOf('nmap $1')[0]).toContain('variable')
    expect(opaqueOf("echo '$HOME'")[0]).not.toContain('variable')
    expect(opaqueOf('echo cost$')[0]).not.toContain('variable')
  })

  it('flags here-documents and here-strings', () => {
    expect(opaqueOf('cat <<EOF')[0]).toContain('here-doc')
    expect(opaqueOf('bash <<< "nmap x"')[0]).toContain('here-doc')
  })

  it('never throws on hostile input', () => {
    const inputs = [
      '',
      '"',
      "'",
      '\\',
      '$(',
      '`',
      '<<',
      '>',
      '2>&',
      '&>',
      '$',
      '${',
      ')',
      '((',
      '\u0000',
      'a'.repeat(5000),
    ]
    for (const input of inputs) expect(() => tokenizeCommand(input)).not.toThrow()
  })
})

describe('stripWrappers', () => {
  it('strips wrappers, their options and VAR=value prefixes', () => {
    const r = stripWrappers([
      'sudo',
      '-E',
      'timeout',
      '30',
      'env',
      'A=1',
      'nice',
      '-n',
      '5',
      'proxychains',
      'nmap',
      'x',
    ])
    expect(r.argv).toEqual(['nmap', 'x'])
    expect(r.wrappers).toEqual(['sudo', 'timeout', 'env', 'nice', 'proxychains'])
  })

  it('handles value options of sudo, timeout, stdbuf, ionice and time', () => {
    expect(stripWrappers(['sudo', '-u', 'root', '--', 'nmap', 'x']).argv).toEqual(['nmap', 'x'])
    expect(stripWrappers(['timeout', '-s', 'KILL', '-k', '5', '30s', 'curl', 'u']).argv).toEqual([
      'curl',
      'u',
    ])
    expect(stripWrappers(['stdbuf', '-oL', '-e', '0', 'nmap']).argv).toEqual(['nmap'])
    expect(stripWrappers(['ionice', '-c', '3', 'nice', '-10', 'nmap']).argv).toEqual(['nmap'])
    expect(stripWrappers(['time', '-f', '%e', 'nohup', 'torsocks', 'curl']).argv).toEqual(['curl'])
    expect(stripWrappers(['proxychains4', '-q', '-f', 'p.conf', 'nmap']).argv).toEqual(['nmap'])
  })

  it('splices env -S and recognises wrapper paths', () => {
    expect(stripWrappers(['/usr/bin/env', '-S', 'nmap -sV', 'x']).argv).toEqual([
      'nmap',
      '-sV',
      'x',
    ])
    expect(stripWrappers(['FOO=1', 'BAR=2', 'command', '-p', 'exec', 'nmap']).argv).toEqual([
      'nmap',
    ])
  })

  it('drops leading shell reserved words', () => {
    expect(stripWrappers(['do', 'nmap', 'x']).argv).toEqual(['nmap', 'x'])
    expect(stripWrappers(['!', 'curl']).argv).toEqual(['curl'])
  })

  it('leaves a bare wrapper empty', () => {
    expect(stripWrappers(['sudo']).argv).toEqual([])
    expect(WRAPPERS.has('proxychains4')).toBe(true)
  })
})
