export type JwtRole = 'admin' | 'user';

// Keep an index signature because jose's generic payload typing can be loose.
export type JwtClaims = {
  sub: string;
  username: string;
  agentId: string;
  role: JwtRole;
  iat?: number;
  exp?: number;
  [key: string]: unknown;
};

