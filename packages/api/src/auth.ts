import { SignJWT, jwtVerify } from 'jose';
import type { KleozConfig } from './config.js';
import type { JwtClaims } from './jwt.js';

function secretFromConfig(cfg: KleozConfig): Uint8Array {
  return new TextEncoder().encode(cfg.jwtSecret);
}

export function computeExpiresAtIso(nowMs: number, expiresIn: string): string {
  // Minimal parser: "<int><unit>" where unit is s|m|h|d. Default to hours on parse failure.
  const m = /^(\d+)\s*([smhd])$/i.exec(expiresIn.trim());
  const n = m ? Number(m[1]) : 12;
  const unit = (m?.[2]?.toLowerCase() ?? 'h') as 's' | 'm' | 'h' | 'd';
  const mult = unit === 's' ? 1000 : unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000;
  return new Date(nowMs + n * mult).toISOString();
}

export async function signToken(cfg: KleozConfig, claims: JwtClaims): Promise<string> {
  return new SignJWT(claims as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(cfg.jwtExpiresIn)
    .sign(secretFromConfig(cfg));
}

export async function verifyToken(cfg: KleozConfig, token: string): Promise<JwtClaims> {
  const out = await jwtVerify<JwtClaims>(token, secretFromConfig(cfg));
  return out.payload;
}
