import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts', 'src/cli/bin.ts'],
  format: 'esm',
  platform: 'node',
  dts: true,
  clean: true,
  // platform 'node' defaults to .mjs/.d.mts; package.json exports name .js/.d.ts.
  fixedExtension: false,
  // The public types name NodeJS.ProcessEnv and Buffer. TypeScript 7 no longer includes every
  // @types package by default, so the declaration file must ask for node's types itself.
  banner: ({ fileName }) =>
    fileName.endsWith('.d.ts') ? '/// <reference types="node" />' : undefined,
})
