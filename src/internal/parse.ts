import type { ProviderId } from '../types.js';
import { malformedHeader } from './failures.js';

/**
 * Splits a `key=value<sep>key=value` header (Stripe, Paddle) into pairs.
 * Whitespace around each element is ignored; the value is everything after
 * the first `=`. Empty elements and elements without a key are rejected.
 */
export function parseKeyValueList(
  value: string,
  separator: string,
  provider: ProviderId,
  header: string,
): readonly (readonly [key: string, value: string])[] {
  return value.split(separator).map((element) => {
    const item = element.trim();
    const eq = item.indexOf('=');
    if (eq <= 0) {
      throw malformedHeader(
        provider,
        header,
        `Header "${header}" must be a "${separator}"-separated list of key=value pairs`,
      );
    }
    return [item.slice(0, eq), item.slice(eq + 1)] as const;
  });
}
