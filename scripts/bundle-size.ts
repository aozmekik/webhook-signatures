/**
 * Measures what each import costs a user's bundle, and checks tree-shaking.
 *
 * For every public verifier, esbuild bundles `export { verifyX } from
 * './dist/index.js'` (minified, ESM, neutral platform), the result is gzipped
 * with zlib level 9, and the sizes are printed as a Markdown table.
 *
 * Fails if a single-provider bundle contains another provider's header name,
 * which would mean tree-shaking broke.
 *
 * Usage: npm run build && node scripts/bundle-size.ts
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { build, version as esbuildVersion } from 'esbuild';

const root = fileURLToPath(new URL('..', import.meta.url));

if (!existsSync(new URL('../dist/index.js', import.meta.url))) {
  console.error('dist/ is missing: run `npm run build` first.');
  process.exit(1);
}

interface Entry {
  readonly label: string;
  readonly code: string;
  /** Header that identifies this provider's code, absent for aggregate entries. */
  readonly marker?: string;
}

const providers: readonly (readonly [name: string, marker: string])[] = [
  ['verifyStripe', 'stripe-signature'],
  ['verifyGitHub', 'x-hub-signature-256'],
  ['verifySlack', 'x-slack-signature'],
  ['verifyShopify', 'x-shopify-hmac-sha256'],
  ['verifyStandardWebhook', 'webhook-signature'],
  ['verifyTwilio', 'x-twilio-signature'],
  ['verifyPaddle', 'paddle-signature'],
  ['verifyLemonSqueezy', 'x-event-name'],
];

const entries: readonly Entry[] = [
  ...providers.map(([name, marker]) => ({
    label: `{ ${name} }`,
    code: `export { ${name} } from './dist/index.js';`,
    marker,
  })),
  {
    label: '{ verifyWebhook } (all providers)',
    code: "export { verifyWebhook } from './dist/index.js';",
  },
  { label: 'webhook-signatures/testing (all sign*)', code: "export * from './dist/testing.js';" },
];

async function measure(code: string): Promise<{ text: string; minified: number; gzipped: number }> {
  const result = await build({
    stdin: { contents: code, resolveDir: root, loader: 'js' },
    bundle: true,
    minify: true,
    format: 'esm',
    platform: 'neutral',
    target: 'es2022',
    write: false,
    logLevel: 'silent',
  });
  const output = result.outputFiles[0];
  if (output === undefined) {
    throw new Error('esbuild produced no output');
  }
  return {
    text: output.text,
    minified: output.contents.byteLength,
    gzipped: gzipSync(output.contents, { level: 9 }).byteLength,
  };
}

const rows: string[] = [];
const failures: string[] = [];
for (const entry of entries) {
  const { text, minified, gzipped } = await measure(entry.code);
  rows.push(
    `| \`${entry.label}\` | ${minified.toLocaleString('en-US')} | ${gzipped.toLocaleString('en-US')} |`,
  );
  if (entry.marker !== undefined) {
    for (const [, other] of providers) {
      // Markers are matched as quoted string literals, exactly as esbuild emits them.
      if (other !== entry.marker && text.includes(`"${other}"`)) {
        failures.push(`${entry.label} contains ${other}: tree-shaking is broken`);
      }
    }
  }
}

console.log(
  `esbuild ${esbuildVersion}, minified ESM, gzip level 9 (node:zlib), Node ${process.version}\n`,
);
console.log('| Import | Minified (bytes) | Min + gzip (bytes) |');
console.log('| --- | ---: | ---: |');
for (const row of rows) {
  console.log(row);
}

if (failures.length > 0) {
  console.error(`\n${failures.join('\n')}`);
  process.exit(1);
}
