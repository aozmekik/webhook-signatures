import { WebhookVerificationError } from '../errors.js';
import type { ProviderId, TimestampToleranceOptions } from '../types.js';

/** Resolved replay-window settings. */
export interface ToleranceWindow {
  /** How old, in seconds, the signed timestamp may be. */
  readonly pastSeconds: number;
  /** How far ahead of `now`, in seconds, the signed timestamp may be (clock skew). */
  readonly futureSeconds: number;
  readonly nowMs: number;
}

/**
 * Validates `toleranceSeconds` and `now` up front, so that a configuration
 * mistake is reported as such instead of surfacing as a confusing
 * verification failure.
 *
 * The window is `toleranceSeconds` in both directions, except that the
 * future side is never narrower than `minimumFutureSeconds`. That floor lets
 * a provider with a very short age window (Paddle) still absorb ordinary
 * clock skew.
 *
 * @throws RangeError for a negative or NaN tolerance.
 * @throws TypeError for a `now` that is not a valid `Date`.
 */
export function resolveTolerance(
  options: TimestampToleranceOptions,
  defaultToleranceSeconds: number,
  minimumFutureSeconds = 0,
): ToleranceWindow {
  const toleranceSeconds = options.toleranceSeconds ?? defaultToleranceSeconds;
  if (
    typeof toleranceSeconds !== 'number' ||
    Number.isNaN(toleranceSeconds) ||
    toleranceSeconds < 0
  ) {
    throw new RangeError('toleranceSeconds must be a non-negative number (or Infinity)');
  }
  const now = options.now ?? new Date();
  if (Object.prototype.toString.call(now) !== '[object Date]' || Number.isNaN(now.getTime())) {
    throw new TypeError('now must be a valid Date');
  }
  return {
    pastSeconds: toleranceSeconds,
    futureSeconds: Math.max(toleranceSeconds, minimumFutureSeconds),
    nowMs: now.getTime(),
  };
}

// Unix seconds as plain ASCII digits. Twelve digits reach the year 33658,
// which keeps every accepted value an exact JavaScript integer.
const UNIX_SECONDS = /^\d{1,12}$/;

/**
 * Parses a Unix timestamp in seconds. Returns `undefined` unless the input is
 * plain decimal digits (no sign, no fraction, no exponent, no whitespace).
 */
export function parseUnixSeconds(value: string): number | undefined {
  return UNIX_SECONDS.test(value) ? Number(value) : undefined;
}

/**
 * Throws `timestamp_out_of_tolerance` if `timestampSeconds` is older than the
 * window's past side or further ahead of `now` than its future side.
 */
export function assertFresh(
  timestampSeconds: number,
  window: ToleranceWindow,
  provider: ProviderId,
  header: string,
): void {
  const ageMs = window.nowMs - timestampSeconds * 1000;
  if (ageMs > window.pastSeconds * 1000) {
    throw new WebhookVerificationError(
      'timestamp_out_of_tolerance',
      `Signed timestamp is too old: ${seconds(ageMs)} ago, tolerance is ${window.pastSeconds}s`,
      { provider, header },
    );
  }
  if (-ageMs > window.futureSeconds * 1000) {
    throw new WebhookVerificationError(
      'timestamp_out_of_tolerance',
      `Signed timestamp is too far in the future: ${seconds(-ageMs)} ahead of now, tolerance is ${window.futureSeconds}s`,
      { provider, header },
    );
  }
}

/** Formats a duration with millisecond precision, so sub-second skew never reads as "0s". */
function seconds(ms: number): string {
  return `${Number((ms / 1000).toFixed(3))}s`;
}

/** Converts a `Date` to whole Unix seconds (rounding down), for signing. */
export function toUnixSeconds(date: Date | undefined): number {
  const ms = (date ?? new Date()).getTime();
  if (Number.isNaN(ms)) {
    throw new TypeError('timestamp must be a valid Date');
  }
  if (ms < 0) {
    throw new RangeError('timestamp must not be before 1970-01-01T00:00:00Z');
  }
  return Math.floor(ms / 1000);
}
