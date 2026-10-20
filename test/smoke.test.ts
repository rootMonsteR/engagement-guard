import { expect, it } from 'vitest'
import { VERSION } from '../src/index.js'

it('exports the package version', () => expect(VERSION).toBe('0.1.1'))
