import path from 'node:path';

function parseList(value: string | undefined, fallback: string[]): string[] {
  if (!value) return fallback;
  const out = value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return out.length ? out : fallback;
}

function parseDurationSeconds(value: string | undefined, fallbackSeconds: number): number {
  if (!value) return fallbackSeconds;
  const m = /^(\d+)(s|m|h|d)$/.exec(value.trim());
  if (!m) return fallbackSeconds;
  const n = Number(m[1]);
  const unit = m[2];
  if (!Number.isFinite(n) || n <= 0) return fallbackSeconds;
  switch (unit) {
    case 's':
      return n;
    case 'm':
      return n * 60;
    case 'h':
      return n * 60 * 60;
    case 'd':
      return n * 24 * 60 * 60;
    default:
      return fallbackSeconds;
  }
}

const repoRoot = process.cwd();
const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.resolve(repoRoot, 'data');

export const config = {
  version: process.env.KLEOZ_VERSION ?? '0.1.0',
  server: {
    port: Number(process.env.PORT ?? 3000),
  },
  dataDir,
  gateway: {
    url: process.env.OPENCLAW_GATEWAY_URL ?? 'ws://127.0.0.1:18789',
    token: process.env.OPENCLAW_GATEWAY_TOKEN ?? '',
    password: process.env.OPENCLAW_GATEWAY_PASSWORD ?? '',
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET ?? 'kleoz-dev-secret',
    jwtExpiresInSeconds: parseDurationSeconds(process.env.JWT_EXPIRES_IN, 7 * 24 * 60 * 60),
    adminUsername: process.env.ADMIN_USERNAME ?? 'admin',
    adminPassword: process.env.ADMIN_PASSWORD ?? 'admin1234',
  },
  agents: {
    allowed: parseList(process.env.AGENTS_ALLOWED, ['main']),
  },
  uploads: {
    dir: process.env.UPLOADS_PATH ? path.resolve(process.env.UPLOADS_PATH) : path.resolve(dataDir, 'uploads'),
    ttlSeconds: parseDurationSeconds(process.env.UPLOADS_TTL, 60 * 60),
    maxSizeBytes: Number(process.env.MAX_UPLOAD_SIZE ?? 50 * 1024 * 1024),
  },
  rateLimits: {
    login: { points: 5, windowSeconds: 60 },
    send: { points: 30, windowSeconds: 60 },
    upload: { points: 10, windowSeconds: 60 },
    wsMessage: { points: 60, windowSeconds: 60 },
  },
} as const;
