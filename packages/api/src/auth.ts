import { SignJWT, jwtVerify } from 'jose';
import type { JwtClaims } from './types.js';
import { config } from './config.js';

const secret = new TextEncoder().encode(config.auth.jwtSecret);

// In-memory revocation list by jti (until token expiry).
const revoked = new Map<string, number>(); // jti -> exp (seconds)

function gcRevoked(nowSeconds: number): void {
  for (const [jti, exp] of revoked.entries()) {
    if (exp <= nowSeconds) revoked.delete(jti);
  }
}

export async function signToken(claims: JwtClaims): Promise<string> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  gcRevoked(nowSeconds);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(claims.jti)
    .setIssuedAt()
    .setExpirationTime(nowSeconds + config.auth.jwtExpiresInSeconds)
    .sign(secret);
}

export async function verifyToken(token: string): Promise<JwtClaims> {
  const out = await jwtVerify<JwtClaims>(token, secret);
  const nowSeconds = Math.floor(Date.now() / 1000);
  gcRevoked(nowSeconds);
  const jti = out.payload.jti;
  if (typeof jti === 'string') {
    const exp = revoked.get(jti);
    if (exp && exp > nowSeconds) {
      throw new Error('Token revoked');
    }
  }
  return out.payload;
}

export async function revokeToken(token: string): Promise<void> {
  const out = await jwtVerify<JwtClaims>(token, secret);
  const jti = out.payload.jti;
  const exp = out.payload.exp;
  const nowSeconds = Math.floor(Date.now() / 1000);
  gcRevoked(nowSeconds);
  if (typeof jti !== 'string') return;
  revoked.set(jti, typeof exp === 'number' ? exp : nowSeconds + config.auth.jwtExpiresInSeconds);
}
