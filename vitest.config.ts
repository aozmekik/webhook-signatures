import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const fromRoot = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    // Examples and tests import the package by name, exactly as users would.
    alias: [
      { find: /^webhook-signatures\/testing$/, replacement: fromRoot('./src/testing.ts') },
      { find: /^webhook-signatures$/, replacement: fromRoot('./src/index.ts') },
    ],
  },
  test: {
    // Wall-clock independence: every timestamp test injects `now`; the SDK
    // interop tests that read the real clock use fake timers.
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
      thresholds: {
        lines: 100,
        functions: 100,
        statements: 100,
        branches: 100,
      },
    },
    projects: [
      {
        extends: true,
        test: {
          name: 'node',
          environment: 'node',
          include: ['test/**/*.test.ts'],
        },
      },
      {
        // The same unit and property suites, run with the Web API
        // implementations of Vercel's edge-runtime (@edge-runtime/vm). Node's
        // globals such as Buffer and process stay visible in this environment,
        // so it does not prove their absence: test/isolation does, by running
        // the bundled library in a bare edge-runtime VM and in workerd.
        extends: true,
        test: {
          name: 'edge',
          environment: 'edge-runtime',
          include: ['test/unit/**/*.test.ts'],
        },
      },
    ],
  },
});
