/**
 * Replay protection for webhooks: process each message id at most once.
 *
 * A valid signature proves who sent a request, not that it is the first time
 * you see it. Providers retry deliveries, and an attacker who captures a
 * request can resend it. Signed timestamps (Stripe, Slack, Standard Webhooks,
 * Paddle) bound that window; remembering ids closes it.
 *
 * The id is recorded in two steps, so that a failure does not lose the event:
 * reserve it with a short lease before doing the work, then mark it done once
 * the side effects succeeded, or release it if they failed so the provider's
 * retry is processed. Marking an id "processed" before the work (a one-step
 * claim) turns any crash or exception into a silently dropped event.
 *
 * When the side effect is a database write, the strongest option needs no
 * separate store: insert the id in the same transaction, behind a unique
 * constraint. Otherwise use a store shared by every instance, with atomic
 * operations: Redis (`SET id processing NX EX lease`, then `SET id done EX ttl`
 * or `DEL id`), a SQL row with a unique key and a status column, or a Durable
 * Object. The in-memory version below is for a single process and for tests.
 */

/** What {@link IdempotencyStore.reserve} found. */
export type Reservation = 'reserved' | 'in-progress' | 'done';

/** Records message ids through processing. */
export interface IdempotencyStore {
  /**
   * Atomically reserves `id` for `leaseSeconds`, unless it is already
   * reserved or done.
   *
   * - `reserved`: the caller owns the id and must call `complete` or `release`.
   * - `in-progress`: another delivery holds an unexpired lease.
   * - `done`: the id was already processed.
   */
  reserve(id: string, leaseSeconds: number): Promise<Reservation>;
  /** Marks `id` as processed and remembers it for `ttlSeconds`. */
  complete(id: string, ttlSeconds: number): Promise<void>;
  /** Drops a reservation after a failure, so that a retry is processed. */
  release(id: string): Promise<void>;
}

/** Timing for {@link processOnce}. */
export interface ProcessOnceOptions {
  /** How long the work may take before another delivery may take the id over. */
  readonly leaseSeconds: number;
  /** How long a processed id is remembered: longer than the provider retries. */
  readonly ttlSeconds: number;
}

/**
 * Runs `work` for `id` unless it already ran or is running.
 *
 * Resolves `processed` after `work` succeeded, `duplicate` when the id was
 * already processed (acknowledge with a 2xx so the provider stops retrying),
 * or `in-progress` while another delivery is processing it (answer with a
 * retryable status such as 409, so the provider tries again later). If
 * `work` throws, the reservation is released and the error is rethrown.
 */
export async function processOnce(
  store: IdempotencyStore,
  id: string,
  options: ProcessOnceOptions,
  work: () => Promise<void>,
): Promise<'processed' | 'duplicate' | 'in-progress'> {
  const reservation = await store.reserve(id, options.leaseSeconds);
  if (reservation === 'done') {
    return 'duplicate';
  }
  if (reservation === 'in-progress') {
    return 'in-progress';
  }
  try {
    await work();
  } catch (error) {
    await store.release(id);
    throw error;
  }
  await store.complete(id, options.ttlSeconds);
  return 'processed';
}

interface Entry {
  readonly state: 'in-progress' | 'done';
  readonly expiresAt: number;
}

const SWEEP_INTERVAL_MS = 60_000;

/** Single-process store with expiry. Not shared across instances. */
export class MemoryIdempotencyStore implements IdempotencyStore {
  readonly #entries = new Map<string, Entry>();
  readonly #now: () => number;
  #nextSweep = 0;

  /** @param now - Clock in milliseconds, injectable for tests. */
  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  reserve(id: string, leaseSeconds: number): Promise<Reservation> {
    const now = this.#now();
    this.#sweep(now);
    const entry = this.#entries.get(id);
    if (entry !== undefined && entry.expiresAt > now) {
      return Promise.resolve(entry.state);
    }
    this.#entries.set(id, { state: 'in-progress', expiresAt: now + leaseSeconds * 1000 });
    return Promise.resolve('reserved');
  }

  complete(id: string, ttlSeconds: number): Promise<void> {
    this.#entries.set(id, { state: 'done', expiresAt: this.#now() + ttlSeconds * 1000 });
    return Promise.resolve();
  }

  release(id: string): Promise<void> {
    this.#entries.delete(id);
    return Promise.resolve();
  }

  /** Drops expired entries at most once a minute, instead of scanning on every call. */
  #sweep(now: number): void {
    if (now < this.#nextSweep) {
      return;
    }
    this.#nextSweep = now + SWEEP_INTERVAL_MS;
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt <= now) {
        this.#entries.delete(id);
      }
    }
  }

  /** Number of stored ids, expired ones included until the next sweep. */
  get size(): number {
    return this.#entries.size;
  }
}
