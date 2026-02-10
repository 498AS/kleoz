import { SignJWT, jwtVerify } from 'jose';
import type { JwtClaims } from './types.js';

const secret = new TextEncoder().encode(process.env.JWT_SECRET ?? 'kleoz-dev-secret');

export async function signToken(claims: JwtClaims): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('12h')
    .sign(secret);
}

export async function verifyToken(token: string): Promise<JwtClaims> {
  const out = await jwtVerify<JwtClaims>(token, secret);
  return out.payload;
}
