import { expect } from 'vitest';
import { WebhookVerificationError } from 'webhook-signatures';
import type { WebhookVerificationErrorCode } from 'webhook-signatures';

/** A fixed instant used as "now" so no test depends on the wall clock. */
export const NOW = new Date('2026-03-14T15:09:26Z');

/** Returns `date` shifted by `seconds`. */
export function shift(date: Date, seconds: number): Date {
  return new Date(date.getTime() + seconds * 1000);
}

/** Awaits `promise` and asserts it rejects with a WebhookVerificationError of `code`. */
export async function expectCode(
  promise: Promise<unknown>,
  code: WebhookVerificationErrorCode,
): Promise<WebhookVerificationError> {
  const error: unknown = await promise.then(
    () => undefined,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(WebhookVerificationError);
  const verificationError = error as WebhookVerificationError;
  expect(verificationError.code, verificationError.message).toBe(code);
  return verificationError;
}

/** Returns a copy of `headers` with `name` replaced (or removed when `value` is undefined). */
export function withHeader(
  headers: Record<string, string>,
  name: string,
  value: string | undefined,
): Record<string, string> {
  const copy = Object.fromEntries(Object.entries(headers).filter(([key]) => key !== name));
  if (value !== undefined) {
    copy[name] = value;
  }
  return copy;
}

/** Replaces the last character of `text` with a different one. */
export function tamper(text: string): string {
  const last = text.at(-1) ?? 'a';
  return text.slice(0, -1) + (last === 'x' ? 'y' : 'x');
}
