import fs from 'node:fs';
import path from 'node:path';

export type KleozConfig = {
  port: number;
  host: string;
  nodeEnv: string;
  jwtSecret: string;
  jwtExpiresIn: string; // jose supports "7d", "12h", etc.
  databasePath: string;
  uploadsPath: string;
  maxUploadSizeBytes: number;
  adminUsername: string;
  adminPassword: string;
  gateway: {
    url: string;
    token?: string;
    password?: string;
    minProtocol: number;
    maxProtocol: number;
  };
};

function envStr(name: string, fallback = ''): string {
  const v = process.env[name];
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : fallback;
}

let envBootstrapped = false;

function loadEnvFile(filePath: string): void {
  if (!fs.existsSync(filePath)) return;
  const txt = fs.readFileSync(filePath, 'utf8');
  for (const line of txt.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx <= 0) continue;
    const key = trimmed.slice(0, idx).trim();
    let val = trimmed.slice(idx + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!key) continue;
    if (process.env[key] != null) continue; // don't override explicit env
    process.env[key] = val;
  }
}

function bootstrapEnv(): void {
  if (envBootstrapped) return;
  envBootstrapped = true;

  // Ensure env files are discovered even when bun is invoked with `--cwd packages/api`.
  const repoRoot = path.resolve(import.meta.dir, '../../..');
  const apiDir = path.resolve(repoRoot, 'packages/api');

  loadEnvFile(path.join(repoRoot, '.env'));
  loadEnvFile(path.join(repoRoot, '.env.local'));
  loadEnvFile(path.join(apiDir, '.env'));
  loadEnvFile(path.join(apiDir, '.env.local'));
}

function envNum(name: string, fallback: number): number {
  const raw = envStr(name, '');
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

export function normalizeGatewayUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return 'ws://127.0.0.1:18789';
  if (trimmed.startsWith('https://')) return `wss://${trimmed.slice('https://'.length)}`;
  if (trimmed.startsWith('http://')) return `ws://${trimmed.slice('http://'.length)}`;
  if (trimmed.startsWith('wss://') || trimmed.startsWith('ws://')) return trimmed;
  return `ws://${trimmed}`;
}

export function loadConfig(): KleozConfig {
  bootstrapEnv();

  // Accept both OPENCLAW_* and CLAWDBOT_* (webclaw uses CLAWDBOT_*).
  const gatewayUrl = normalizeGatewayUrl(
    envStr('OPENCLAW_GATEWAY_URL', envStr('CLAWDBOT_GATEWAY_URL', 'ws://127.0.0.1:18789')),
  );
  const gatewayToken = envStr('OPENCLAW_GATEWAY_TOKEN', envStr('CLAWDBOT_GATEWAY_TOKEN', ''));
  const gatewayPassword = envStr('OPENCLAW_GATEWAY_PASSWORD', envStr('CLAWDBOT_GATEWAY_PASSWORD', ''));

  const jwtSecret = envStr('JWT_SECRET', 'kleoz-dev-secret');
  const jwtExpiresIn = envStr('JWT_EXPIRES_IN', '7d');

  return {
    port: envNum('PORT', 3000),
    host: envStr('HOST', '0.0.0.0'),
    nodeEnv: envStr('NODE_ENV', 'development'),
    jwtSecret,
    jwtExpiresIn,
    databasePath: envStr('DATABASE_PATH', './data/kleoz.db'),
    uploadsPath: envStr('UPLOADS_PATH', './data/uploads'),
    maxUploadSizeBytes: envNum('MAX_UPLOAD_SIZE', 50 * 1024 * 1024),
    adminUsername: envStr('ADMIN_USERNAME', 'admin'),
    adminPassword: envStr('ADMIN_PASSWORD', 'admin1234'),
    gateway: {
      url: gatewayUrl,
      token: gatewayToken || undefined,
      password: gatewayPassword || undefined,
      minProtocol: 3,
      maxProtocol: 3,
    },
  };
}
