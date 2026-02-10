import bcrypt from 'bcryptjs';
import type { Message, Session, User } from './types.js';

export class InMemoryStore {
  users = new Map<string, User>();
  sessions = new Map<string, Session>();

  constructor() {
    const adminId = crypto.randomUUID();
    this.users.set(adminId, {
      id: adminId,
      username: 'admin',
      passwordHash: bcrypt.hashSync('admin1234', 10),
      role: 'admin',
      agentId: 'main',
    });
  }

  findUserByUsername(username: string): User | undefined {
    return Array.from(this.users.values()).find((u) => u.username === username);
  }

  createUser(input: Omit<User, 'id' | 'passwordHash'> & { password: string }): User {
    const id = crypto.randomUUID();
    const user: User = {
      id,
      username: input.username,
      passwordHash: bcrypt.hashSync(input.password, 10),
      role: input.role,
      agentId: input.agentId,
    };
    this.users.set(id, user);
    return user;
  }

  upsertSession(sessionKey: string, participants: string[]): Session {
    const existing = this.sessions.get(sessionKey);
    if (existing) {
      return existing;
    }
    const now = new Date().toISOString();
    const session: Session = {
      key: sessionKey,
      title: sessionKey.split(':').slice(-1)[0] ?? sessionKey,
      participants,
      createdAt: now,
      updatedAt: now,
      messages: [],
    };
    this.sessions.set(sessionKey, session);
    return session;
  }

  appendMessage(sessionKey: string, message: Omit<Message, 'id' | 'createdAt'>): Message {
    const session = this.sessions.get(sessionKey);
    if (!session) {
      throw new Error('Session not found');
    }
    const full: Message = {
      ...message,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    };
    session.messages.push(full);
    session.updatedAt = full.createdAt;
    return full;
  }
}
