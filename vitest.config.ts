import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    // The examples import the package by name; under the root suite that is the source tree.
    alias: { 'engagement-guard': fileURLToPath(new URL('./src/index.ts', import.meta.url)) },
  },
  test: {
    include: ['test/**/*.test.ts', 'examples/**/*.test.ts'],
    exclude: ['**/node_modules/**', '_snapshot/**'],
    environment: 'node',
    passWithNoTests: true,
    // Tests are expected to finish in well under a second; the timeout is only a hang detector and
    // must tolerate the slow Windows CI runner, where a cold module import alone has taken 6 s.
    testTimeout: 20_000,
  },
})
