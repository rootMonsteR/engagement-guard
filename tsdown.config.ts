import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts', 'src/cli/bin.ts'],
  format: 'esm',
  platform: 'node',
  dts: true,
  clean: true,
  // platform 'node' defaults to .mjs/.d.mts; package.json exports name .js/.d.ts.
  fixedExtension: false,
})
