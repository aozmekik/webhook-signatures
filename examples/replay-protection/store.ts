/**
 * Replay protection for webhooks: remember which message ids were processed.
 *
 * A valid signature proves who sent a request, not that it is the first time
 * you see it. Providers retry deliveries, and an attacker who captures a
 * request can resend it. Signed timestamps (Stripe, Slack, Standard Webhooks,
 * Paddle) bound that window; remembering ids closes it.
 *
 * Use a shared store with atomic "set if absent" in production (Redis
 * `SET key 1 NX EX ttl`, a unique index in SQL, Cloudflare KV / Durable
 * Objects). This in-memory version is for a single process and for tests.
 */

/** Records ids that were already handled. */
export interface IdempotencyStore {
  /**
   * Atomically records `id`. Resolves `true` the first time an id is seen
   * within `ttlSeconds`, `false` for every repeat.
   */
  claim(id: string, ttlSeconds: number): Promise<boolean>;
}

/** Single-process store with expiry. Not shared across instances. */
export class MemoryIdempotencyStore implements IdempotencyStore {
  readonly #expiresAt = new Map<string, number>();
  readonly #now: () => number;

  /** @param now - Clock in milliseconds, injectable for tests. */
  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  claim(id: string, ttlSeconds: number): Promise<boolean> {
    const now = this.#now();
    for (const [key, expiry] of this.#expiresAt) {
      if (expiry <= now) {
        this.#expiresAt.delete(key);
      }
    }
    if (this.#expiresAt.has(id)) {
      return Promise.resolve(false);
    }
    this.#expiresAt.set(id, now + ttlSeconds * 1000);
    return Promise.resolve(true);
  }
}
