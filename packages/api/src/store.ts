import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import bcrypt from 'bcryptjs';

import { config } from './config.js';
import type { ChatMessage, Role, Session, User } from './types.js';

type SQLiteRunResult = { changes: number };
type SQLiteStmt = {
  get: (...args: unknown[]) => unknown;
  all: (...args: unknown[]) => unknown[];
  run: (...args: unknown[]) => SQLiteRunResult;
};
type SQLiteDb = {
  exec: (sql: string) => void;
  prepare: (sql: string) => SQLiteStmt;
};

const require = createRequire(import.meta.url);
const { DatabaseSync } = require('node:sqlite') as { DatabaseSync: new (path: string) => SQLiteDb };

function ensureDir(p: string): void {
  fs.mkdirSync(p, { recursive: true });
}

function sessionAgentId(sessionKey: string): string | undefined {
  const m = /^agent:([^:]+):/.exec(sessionKey);
  return m?.[1];
}

function sessionKind(sessionKey: string): Session['kind'] {
  if (/\b:dm:/.test(sessionKey)) return 'dm';
  if (/\b:group:/.test(sessionKey)) return 'group';
  if (/\b:channel:/.test(sessionKey)) return 'channel';
  return 'other';
}

function sessionChannel(sessionKey: string): string {
  // Best-effort: agent:<id>:<channel>:...
  const parts = sessionKey.split(':');
  if (parts.length >= 3) return parts[2] || 'unknown';
  return 'unknown';
}

function transcriptRelPath(sessionKey: string): string {
  // Stable, filesystem-safe.
  const name = Buffer.from(sessionKey, 'utf8').toString('base64url');
  return path.posix.join('transcripts', `${name}.jsonl`);
}

function apiUploadUrl(id: string): string {
  return `/api/uploads/${encodeURIComponent(id)}`;
}

type Access = { userId: string; isAdmin: boolean; agentId: string };

export class SQLiteStore {
  private db: SQLiteDb;
  private dbPath: string;
  private transcriptsDir: string;
  private uploadsDir: string;
  private dataDir: string;

  constructor(opts?: { dataDir?: string; dbPath?: string; uploadsDir?: string }) {
    this.dataDir = opts?.dataDir ? path.resolve(opts.dataDir) : config.dataDir;
    ensureDir(this.dataDir);
    this.transcriptsDir = path.resolve(this.dataDir, 'transcripts');
    this.uploadsDir = opts?.uploadsDir ? path.resolve(opts.uploadsDir) : config.uploads.dir;
    ensureDir(this.transcriptsDir);
    ensureDir(this.uploadsDir);

    this.dbPath = opts?.dbPath
      ? path.resolve(opts.dbPath)
      : process.env.DATABASE_PATH
        ? path.resolve(process.env.DATABASE_PATH)
        : path.resolve(this.dataDir, 'kleoz.db');
    this.db = new DatabaseSync(this.dbPath);
    this.migrate();
    this.ensureAdminUser();
    this.gcUploads().catch(() => {});
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_login_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS sessions (
        key TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        channel TEXT NOT NULL,
        display_name TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        model TEXT,
        total_tokens INTEGER,
        context_tokens INTEGER,
        transcript_path TEXT NOT NULL,
        participants_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS uploads (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL,
        rel_path TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
  }

  private ensureAdminUser(): void {
    const row = this.db.prepare(`SELECT id FROM users WHERE username = ?`).get(config.auth.adminUsername) as { id: string } | undefined;
    if (row?.id) return;
    const id = crypto.randomUUID();
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO users (id, username, password_hash, agent_id, role, created_at, updated_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(id, config.auth.adminUsername, bcrypt.hashSync(config.auth.adminPassword, 10), 'main', 'admin', now, now);
  }

  // --- Users

  findUserByUsername(username: string): User | undefined {
    const row = this.db
      .prepare(
        `SELECT id, username, password_hash as passwordHash, agent_id as agentId, role, created_at as createdAt, updated_at as updatedAt, last_login_at as lastLoginAt
         FROM users WHERE username = ?`,
      )
      .get(username) as User | undefined;
    return row;
  }

  getUserById(id: string): User | undefined {
    const row = this.db
      .prepare(
        `SELECT id, username, password_hash as passwordHash, agent_id as agentId, role, created_at as createdAt, updated_at as updatedAt, last_login_at as lastLoginAt
         FROM users WHERE id = ?`,
      )
      .get(id) as User | undefined;
    return row;
  }

  listUsers(): User[] {
    const rows = this.db
      .prepare(
        `SELECT id, username, password_hash as passwordHash, agent_id as agentId, role, created_at as createdAt, updated_at as updatedAt, last_login_at as lastLoginAt
         FROM users ORDER BY created_at ASC`,
      )
      .all() as User[];
    return rows;
  }

  createUser(input: { username: string; password: string; role: Role; agentId: string }): User {
    const existing = this.findUserByUsername(input.username);
    if (existing) throw new Error('User already exists');
    const id = crypto.randomUUID();
    const now = Date.now();
    const user: User = {
      id,
      username: input.username,
      passwordHash: bcrypt.hashSync(input.password, 10),
      role: input.role,
      agentId: input.agentId,
      createdAt: now,
      updatedAt: now,
      lastLoginAt: undefined,
    };
    this.db
      .prepare(
        `INSERT INTO users (id, username, password_hash, agent_id, role, created_at, updated_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(user.id, user.username, user.passwordHash, user.agentId, user.role, user.createdAt, user.updatedAt);
    return user;
  }

  updateUser(userId: string, patch: { username?: string; password?: string; role?: Role; agentId?: string }): boolean {
    const u = this.getUserById(userId);
    if (!u) return false;
    const now = Date.now();
    const username = patch.username ?? u.username;
    const passwordHash = patch.password ? bcrypt.hashSync(patch.password, 10) : u.passwordHash;
    const role = patch.role ?? u.role;
    const agentId = patch.agentId ?? u.agentId;
    this.db
      .prepare(
        `UPDATE users SET username = ?, password_hash = ?, role = ?, agent_id = ?, updated_at = ? WHERE id = ?`,
      )
      .run(username, passwordHash, role, agentId, now, userId);
    return true;
  }

  deleteUser(userId: string): boolean {
    const out = this.db.prepare(`DELETE FROM users WHERE id = ?`).run(userId) as { changes: number };
    return out.changes > 0;
  }

  touchUserLogin(userId: string): void {
    const now = Date.now();
    this.db.prepare(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`).run(now, now, userId);
  }

  countUsers(): number {
    const row = this.db.prepare(`SELECT COUNT(*) as n FROM users`).get() as { n: number };
    return row.n ?? 0;
  }

  // --- Sessions

  ensureSession(sessionKey: string, access: Access): Session | null {
    const agent = sessionAgentId(sessionKey);
    if (!access.isAdmin) {
      if (agent && agent !== access.agentId) return null;
      if (agent && !config.agents.allowed.includes(agent)) return null;
    }

    const existing = this.getSession(sessionKey, access);
    if (existing) return existing as any;

    // Create new session owned by this user.
    const now = Date.now();
    const session: Session = {
      key: sessionKey,
      sessionId: crypto.randomUUID(),
      kind: sessionKind(sessionKey),
      channel: sessionChannel(sessionKey),
      displayName: sessionKey.split(':').slice(-1)[0] ?? sessionKey,
      createdAt: now,
      updatedAt: now,
      transcriptPath: transcriptRelPath(sessionKey),
      participants: [access.userId],
    };

    ensureDir(path.dirname(path.resolve(this.dataDir, session.transcriptPath)));
    const absTranscript = path.resolve(this.dataDir, session.transcriptPath);
    if (!fs.existsSync(absTranscript)) fs.writeFileSync(absTranscript, '');

    this.db
      .prepare(
        `INSERT INTO sessions (key, session_id, kind, channel, display_name, created_at, updated_at, model, total_tokens, context_tokens, transcript_path, participants_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`,
      )
      .run(
        session.key,
        session.sessionId,
        session.kind,
        session.channel ?? 'unknown',
        session.displayName ?? null,
        session.createdAt,
        session.updatedAt,
        session.transcriptPath,
        JSON.stringify(session.participants),
      );

    return session;
  }

  listSessions(opts: { userId: string; isAdmin: boolean; agentId: string; limit: number; activeMinutes?: number; kind?: 'dm' | 'group' | 'channel' }): {
    sessions: Omit<Session, 'participants' | 'createdAt'>[];
    count: number;
  } {
    const where: string[] = [];
    const params: unknown[] = [];

    if (!opts.isAdmin) {
      where.push(`key LIKE ?`);
      params.push(`agent:${opts.agentId}:%`);
    }
    if (opts.activeMinutes && Number.isFinite(opts.activeMinutes)) {
      where.push(`updated_at >= ?`);
      params.push(Date.now() - opts.activeMinutes * 60_000);
    }
    if (opts.kind) {
      where.push(`kind = ?`);
      params.push(opts.kind);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const countRow = this.db.prepare(`SELECT COUNT(*) as n FROM sessions ${whereSql}`).get(...params) as { n: number };

    const rows = this.db
      .prepare(
        `SELECT key, session_id as sessionId, kind, channel, display_name as displayName, updated_at as updatedAt, model, total_tokens as totalTokens, context_tokens as contextTokens, transcript_path as transcriptPath
         FROM sessions ${whereSql}
         ORDER BY updated_at DESC
         LIMIT ?`,
      )
      .all(...params, opts.limit) as any[];

    return { sessions: rows, count: countRow.n ?? rows.length };
  }

  getSession(sessionKey: string, access: Access): (Omit<Session, 'participants'> & { participants: string[] }) | undefined {
    const row = this.db
      .prepare(
        `SELECT key, session_id as sessionId, kind, channel, display_name as displayName, created_at as createdAt, updated_at as updatedAt, model, total_tokens as totalTokens, context_tokens as contextTokens, transcript_path as transcriptPath, participants_json as participantsJson
         FROM sessions WHERE key = ?`,
      )
      .get(sessionKey) as any;
    if (!row) return undefined;
    const participants = JSON.parse(row.participantsJson ?? '[]') as string[];
    const agent = sessionAgentId(sessionKey);
    if (!access.isAdmin) {
      if (agent && agent !== access.agentId) return undefined;
      if (agent && !config.agents.allowed.includes(agent)) return undefined;
    }
    return {
      key: row.key,
      sessionId: row.sessionId,
      kind: row.kind,
      channel: row.channel,
      displayName: row.displayName ?? undefined,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      model: row.model ?? undefined,
      totalTokens: row.totalTokens ?? undefined,
      contextTokens: row.contextTokens ?? undefined,
      transcriptPath: row.transcriptPath,
      participants,
    };
  }

  deleteSession(sessionKey: string, access: Access): { ok: true; deleted: { sessionKey: string; transcriptDeleted: boolean } } | null {
    const s = this.getSession(sessionKey, access);
    if (!s) return null;
    if (!access.isAdmin && !s.participants.includes(access.userId)) return null;
    const abs = path.resolve(this.dataDir, s.transcriptPath);
    let transcriptDeleted = false;
    try {
      fs.unlinkSync(abs);
      transcriptDeleted = true;
    } catch {
      transcriptDeleted = false;
    }
    this.db.prepare(`DELETE FROM sessions WHERE key = ?`).run(sessionKey);
    return { ok: true, deleted: { sessionKey, transcriptDeleted } };
  }

  countSessions(): { total: number; active: number } {
    const totalRow = this.db.prepare(`SELECT COUNT(*) as n FROM sessions`).get() as { n: number };
    const activeRow = this.db.prepare(`SELECT COUNT(*) as n FROM sessions WHERE updated_at >= ?`).get(Date.now() - 60 * 60_000) as { n: number };
    return { total: totalRow.n ?? 0, active: activeRow.n ?? 0 };
  }

  // --- Transcript / History

  appendToTranscript(sessionKey: string, msg: ChatMessage): void {
    const s = this.getSession(sessionKey, { userId: 'internal', isAdmin: true, agentId: 'internal' });
    const rel = s?.transcriptPath ?? transcriptRelPath(sessionKey);
    const abs = path.resolve(this.dataDir, rel);
    ensureDir(path.dirname(abs));
    fs.appendFileSync(abs, `${JSON.stringify(msg)}\n`, 'utf8');
    this.db.prepare(`UPDATE sessions SET updated_at = ? WHERE key = ?`).run(Date.now(), sessionKey);
  }

  getSessionHistory(
    sessionKey: string,
    opts: Access & { limit: number; includeTools: boolean; before?: string },
  ): { messages: ChatMessage[]; hasMore: boolean; nextCursor?: string } | null {
    const s = this.getSession(sessionKey, opts);
    if (!s) return null;
    const abs = path.resolve(this.dataDir, s.transcriptPath);
    if (!fs.existsSync(abs)) return { messages: [], hasMore: false };
    const raw = fs.readFileSync(abs, 'utf8');
    const lines = raw
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    let msgs: ChatMessage[] = [];
    for (const line of lines) {
      try {
        const m = JSON.parse(line) as ChatMessage;
        if (!opts.includeTools && m.role === 'tool') continue;
        msgs.push(m);
      } catch {
        // ignore malformed line
      }
    }

    // Pagination: "before" is message id (exclusive).
    let end = msgs.length;
    if (opts.before) {
      const idx = msgs.findIndex((m) => m.id === opts.before);
      if (idx >= 0) end = idx;
    }
    const slice = msgs.slice(0, end);
    const start = Math.max(0, slice.length - opts.limit);
    const page = slice.slice(start);
    const hasMore = start > 0;
    const nextCursor = hasMore ? page[0]?.id : undefined;
    return { messages: page, hasMore, nextCursor };
  }

  // --- Uploads

  async saveUpload(file: File): Promise<{ id: string; filename: string; mimeType: string; size: number; url: string; expiresAt: string }> {
    const id = crypto.randomUUID();
    const ext = path.extname(file.name || '') || '';
    const rel = path.posix.join('uploads', `${id}${ext}`);
    const abs = path.resolve(this.uploadsDir, `${id}${ext}`);
    ensureDir(path.dirname(abs));
    const bytes = new Uint8Array(await file.arrayBuffer());
    await fsp.writeFile(abs, bytes);

    const expiresAt = Date.now() + config.uploads.ttlSeconds * 1000;
    this.db
      .prepare(`INSERT INTO uploads (id, filename, mime_type, size, rel_path, expires_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(id, file.name || 'upload', file.type || 'application/octet-stream', bytes.byteLength, abs, expiresAt);

    return { id, filename: file.name || 'upload', mimeType: file.type || 'application/octet-stream', size: bytes.byteLength, url: apiUploadUrl(id), expiresAt: new Date(expiresAt).toISOString() };
  }

  getUploadPath(uploadId: string): { path: string; mimeType: string; size: number } | null {
    const row = this.db
      .prepare(`SELECT rel_path as relPath, mime_type as mimeType, size, expires_at as expiresAt FROM uploads WHERE id = ?`)
      .get(uploadId) as any;
    if (!row) return null;
    if (row.expiresAt <= Date.now()) {
      try {
        fs.unlinkSync(row.relPath);
      } catch {}
      this.db.prepare(`DELETE FROM uploads WHERE id = ?`).run(uploadId);
      return null;
    }
    return { path: row.relPath, mimeType: row.mimeType, size: row.size };
  }

  async readUploadBytes(p: string): Promise<Uint8Array> {
    const b = await fsp.readFile(p);
    return new Uint8Array(b);
  }

  private async gcUploads(): Promise<void> {
    const rows = this.db.prepare(`SELECT id, rel_path as relPath, expires_at as expiresAt FROM uploads`).all() as any[];
    for (const r of rows) {
      if (r.expiresAt <= Date.now()) {
        try {
          await fsp.unlink(r.relPath);
        } catch {}
        this.db.prepare(`DELETE FROM uploads WHERE id = ?`).run(r.id);
      }
    }
  }
}
