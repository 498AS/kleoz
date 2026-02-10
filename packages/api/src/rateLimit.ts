import type { Context, Next } from 'hono';

type Bucket = { count: number; resetAtMs: number };

export function createRateLimiter() {
  const buckets = new Map<string, Bucket>();

  function gc(now: number): void {
    for (const [k, v] of buckets.entries()) {
      if (v.resetAtMs <= now) buckets.delete(k);
    }
  }

  return function rateLimit(opts: {
    key: (c: Context) => string;
    points: number;
    windowSeconds: number;
  }) {
    return async (c: Context, next: Next) => {
      const now = Date.now();
      gc(now);
      const k = opts.key(c);
      const b = buckets.get(k);
      if (!b || b.resetAtMs <= now) {
        buckets.set(k, { count: 1, resetAtMs: now + opts.windowSeconds * 1000 });
        return next();
      }
      if (b.count >= opts.points) {
        const retryAfterSeconds = Math.max(1, Math.ceil((b.resetAtMs - now) / 1000));
        c.header('retry-after', String(retryAfterSeconds));
        return c.json({ error: { code: 'RATE_LIMIT', message: 'Too many requests' } }, 429);
      }
      b.count += 1;
      return next();
    };
  };
}

