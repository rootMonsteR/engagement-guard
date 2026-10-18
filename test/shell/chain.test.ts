import { expect, it } from 'vitest'
import { splitShellChain } from '../../src/shell/chain.js'

it('splits on ; && || | and newline', () =>
  expect(splitShellChain('a; b && c || d | e\nf').segments).toEqual([
    'a',
    ' b ',
    ' c ',
    ' d ',
    ' e',
    'f',
  ]))
it('splits on substitution openers and a lone &', () =>
  expect(splitShellChain('echo $(id) & x').operators).toEqual(['$(', '&']))
it('does not split a redirection &', () =>
  expect(splitShellChain('cmd 2>&1').operators).toEqual([]))
