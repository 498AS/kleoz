export type Role = 'admin' | 'user';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  agentId: string;
  role: Role;
}

export interface Message {
  id: string;
  sessionKey: string;
  sender: string;
  senderUserId: string;
  body: string;
  createdAt: string;
  mentionsAgent: boolean;
}

export interface Session {
  key: string;
  title: string;
  participants: string[];
  updatedAt: string;
  createdAt: string;
  messages: Message[];
}

export interface JwtClaims {
  sub: string;
  username: string;
  role: Role;
  agentId: string;
}
