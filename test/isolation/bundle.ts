import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('../..', import.meta.url));

/**
 * Bundles `contents` (which may import ./test/isolation/scenario.ts and
 * ./src/*) for the neutral platform, where Node built-ins cannot be resolved.
 */
export async function bundleForNeutralPlatform(
  contents: string,
  format: 'esm' | 'iife',
): Promise<string> {
  const result = await build({
    stdin: { contents, resolveDir: root, loader: 'ts' },
    bundle: true,
    write: false,
    platform: 'neutral',
    format,
    target: 'es2022',
    logLevel: 'silent',
  });
  return result.outputFiles[0]?.text ?? '';
}

export const EXPECTED_PROVIDERS = [
  'stripe',
  'github',
  'slack',
  'shopify',
  'standard-webhooks',
  'twilio',
  'paddle',
  'lemon-squeezy',
] as const;
