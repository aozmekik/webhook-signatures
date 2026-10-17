// @ts-check
import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

const nodeBuiltinGlobals = [
  'Buffer',
  'process',
  'require',
  'module',
  'global',
  '__dirname',
  '__filename',
  'setImmediate',
  'clearImmediate',
].map((name) => ({
  name,
  message: 'src/ must run on any Web-standard runtime: use Web APIs, not Node.js globals.',
}));

export default defineConfig(
  {
    ignores: ['dist/', 'coverage/', 'node_modules/'],
  },
  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['eslint.config.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    linterOptions: {
      reportUnusedDisableDirectives: 'error',
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/consistent-type-exports': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/no-import-type-side-effects': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      eqeqeq: ['error', 'always'],
      'no-console': 'error',
      curly: ['error', 'all'],
    },
  },
  {
    files: ['src/**/*.ts'],
    rules: {
      'no-restricted-globals': ['error', ...nodeBuiltinGlobals],
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              regex: '^node:',
              message: 'src/ must not import Node.js built-ins.',
            },
          ],
          paths: [
            'crypto',
            'buffer',
            'util',
            'stream',
            'fs',
            'path',
            'url',
            'querystring',
            'events',
            'os',
            'http',
            'https',
          ].map((name) => ({ name, message: 'src/ must not import Node.js built-ins.' })),
        },
      ],
    },
  },
  {
    files: ['test/**/*.ts', 'scripts/**/*.ts', 'examples/**/*.ts', '*.config.ts'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
    },
  },
);
