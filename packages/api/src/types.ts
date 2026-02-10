export type Role = 'admin' | 'user';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  agentId: string;
  role: Role;
  createdAt: number;
  updatedAt: number;
  lastLoginAt?: number;
}

export type ChatRole = 'user' | 'assistant' | 'tool';

export interface ChatMessage {
  id: string;
  role: ChatRole;
  content: string;
  timestamp: string; // ISO8601
  model?: string;
  tokens?: { input?: number; output?: number };
  metadata?: Record<string, unknown>;
}

export interface Session {
  key: string;
  sessionId: string;
  kind: 'dm' | 'group' | 'channel' | 'other';
  channel?: string;
  displayName?: string;
  updatedAt: number; // ms
  createdAt: number; // ms
  model?: string;
  totalTokens?: number;
  contextTokens?: number;
  transcriptPath: string; // relative to data dir
  participants: string[]; // kleoz user ids with access
}

export interface JwtClaims {
  sub: string;
  username: string;
  role: Role;
  agentId: string;
  jti: string;
  // jose adds standard claims; allow them without fighting TS.
  [key: string]: unknown;
}

export type Variables = {
  user: JwtClaims;
};

export interface PresenceEntry {
  instanceId: string;
  host: string;
  ip: string;
  version: string;
  platform?: string;
  deviceFamily?: string;
  modelIdentifier?: string;
  mode: 'ui' | 'webchat' | 'cli' | 'node' | 'backend' | 'probe' | 'test';
  roles?: string[];
  scopes?: string[];
  lastInputSeconds?: number;
  reason: 'self' | 'connect' | 'node-connected' | 'periodic';
  ts: number;
}
