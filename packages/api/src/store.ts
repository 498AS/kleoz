import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import { Database } from 'bun:sqlite';

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

function loadSqliteDb(dbPath: string): SQLiteDb {
  const db = new Database(dbPath);
  return {
    exec: (sql: string) => db.exec(sql),
    prepare: (sql: string) => db.query(sql) as unknown as SQLiteStmt,
  };
}

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
    this.db = loadSqliteDb(this.dbPath);
    this.migrate();
    this.ensureAdminUser();
    this.backfillUserAgentsFromUsers();
    this.backfillDmMembershipFromParticipants();
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

      CREATE TABLE IF NOT EXISTS user_agents (
        user_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, agent_id)
      );
      CREATE INDEX IF NOT EXISTS idx_user_agents_user ON user_agents(user_id);

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
      CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at);

      CREATE TABLE IF NOT EXISTS session_members (
        session_key TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        created_at INTEGER NOT NULL,
        PRIMARY KEY (session_key, user_id)
      );
      CREATE INDEX IF NOT EXISTS idx_session_members_user ON session_members(user_id);

      CREATE TABLE IF NOT EXISTS room_messages (
        id TEXT PRIMARY KEY,
        session_key TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        run_id TEXT,
        model TEXT,
        tokens_json TEXT,
        metadata_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_room_messages_session_created ON room_messages(session_key, created_at_ms);

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
    if (row?.id) {
      const now = Date.now();
      // Ensure the admin is usable with agent filtering even on upgraded DBs.
      const agentRow = this.db.prepare(`SELECT agent_id as agentId FROM users WHERE id = ?`).get(row.id) as any;
      const agentId = agentRow?.agentId ? String(agentRow.agentId) : 'main';
      this.db.prepare(`INSERT OR IGNORE INTO user_agents (user_id, agent_id, created_at) VALUES (?, ?, ?)`).run(row.id, agentId, now);
      return;
    }
    const id = crypto.randomUUID();
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO users (id, username, password_hash, agent_id, role, created_at, updated_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(id, config.auth.adminUsername, bcrypt.hashSync(config.auth.adminPassword, 10), 'main', 'admin', now, now);
    this.db.prepare(`INSERT OR IGNORE INTO user_agents (user_id, agent_id, created_at) VALUES (?, ?, ?)`).run(id, 'main', now);
  }

  private backfillUserAgentsFromUsers(): void {
    const now = Date.now();
    const rows = this.db.prepare(`SELECT id, agent_id as agentId FROM users`).all() as any[];
    for (const r of rows) {
      const userId = String(r.id);
      const agentId = String(r.agentId ?? '').trim();
      if (!userId || !agentId) continue;
      this.db.prepare(`INSERT OR IGNORE INTO user_agents (user_id, agent_id, created_at) VALUES (?, ?, ?)`).run(userId, agentId, now);
    }
  }

  private backfillDmMembershipFromParticipants(): void {
    const now = Date.now();
    const rows = this.db
      .prepare(`SELECT key as sessionKey, participants_json as participantsJson FROM sessions WHERE kind = 'dm'`)
      .all() as any[];
    for (const r of rows) {
      const sessionKey = String(r.sessionKey ?? '').trim();
      if (!sessionKey) continue;
      let participants: unknown = [];
      try {
        participants = JSON.parse(String(r.participantsJson ?? '[]'));
      } catch {
        participants = [];
      }
      const ids = Array.isArray(participants) ? participants.map((x) => String(x)).filter(Boolean) : [];
      for (const userId of ids) {
        this.db
          .prepare(`INSERT OR IGNORE INTO session_members (session_key, user_id, role, created_at) VALUES (?, ?, 'member', ?)`)
          .run(sessionKey, userId, now);
      }
    }
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
    this.db.prepare(`INSERT OR IGNORE INTO user_agents (user_id, agent_id, created_at) VALUES (?, ?, ?)`).run(user.id, user.agentId, now);
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
    if (patch.agentId) {
      this.db.prepare(`INSERT OR IGNORE INTO user_agents (user_id, agent_id, created_at) VALUES (?, ?, ?)`).run(userId, agentId, now);
    }
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

  listAllowedAgents(access: { userId: string; isAdmin: boolean; fallbackAgentId: string }): string[] {
    if (access.isAdmin) return config.agents.allowed.slice();
    const rows = this.db.prepare(`SELECT agent_id as agentId FROM user_agents WHERE user_id = ?`).all(access.userId) as any[];
    const agents = rows.map((r) => String(r.agentId)).filter(Boolean);
    const base = agents.length > 0 ? agents : [access.fallbackAgentId];
    return base.filter((id) => config.agents.allowed.includes(id));
  }

  private isDmSessionKey(sessionKey: string): boolean {
    return sessionKind(sessionKey) === 'dm';
  }

  private canAccessSession(sessionKey: string, access: { userId: string; isAdmin: boolean; allowedAgents: string[] }): boolean {
    if (access.isAdmin) return true;
    const agent = sessionAgentId(sessionKey);
    if (!agent) return false;
    if (!config.agents.allowed.includes(agent)) return false;
    if (!access.allowedAgents.includes(agent)) return false;
    if (this.isDmSessionKey(sessionKey)) {
      const row = this.db.prepare(`SELECT 1 as ok FROM session_members WHERE session_key = ? AND user_id = ?`).get(sessionKey, access.userId) as any;
      return Boolean(row?.ok);
    }
    // Non-DM sessions are visible to all users assigned to the agent.
    return true;
  }

  ensureSession(
    sessionKey: string,
    access: { userId: string; isAdmin: boolean; allowedAgents: string[] },
  ): { session: Session; created: boolean } | null {
    const existingRow = this.db
      .prepare(
        `SELECT key, session_id as sessionId, kind, channel, display_name as displayName, created_at as createdAt, updated_at as updatedAt, model, total_tokens as totalTokens, context_tokens as contextTokens, transcript_path as transcriptPath
         FROM sessions WHERE key = ?`,
      )
      .get(sessionKey) as any;

    if (existingRow) {
      // Session exists: do not allow implicit "join" to DM by guessing key.
      if (!this.canAccessSession(sessionKey, access)) return null;
      const session: Session = {
        key: String(existingRow.key),
        sessionId: String(existingRow.sessionId),
        kind: existingRow.kind,
        channel: existingRow.channel,
        displayName: existingRow.displayName ?? undefined,
        createdAt: Number(existingRow.createdAt),
        updatedAt: Number(existingRow.updatedAt),
        model: existingRow.model ?? undefined,
        totalTokens: existingRow.totalTokens ?? undefined,
        contextTokens: existingRow.contextTokens ?? undefined,
        transcriptPath: String(existingRow.transcriptPath),
        participants: [],
      };
      return { session, created: false };
    }

    // New session: validate agent access.
    if (!access.isAdmin) {
      const agent = sessionAgentId(sessionKey);
      if (!agent) return null;
      if (!config.agents.allowed.includes(agent)) return null;
      if (!access.allowedAgents.includes(agent)) return null;
    }

    const now = Date.now();
    const kind = sessionKind(sessionKey);
    const session: Session = {
      key: sessionKey,
      sessionId: crypto.randomUUID(),
      kind,
      channel: sessionChannel(sessionKey),
      displayName: sessionKey.split(':').slice(-1)[0] ?? sessionKey,
      createdAt: now,
      updatedAt: now,
      transcriptPath: transcriptRelPath(sessionKey),
      participants: [],
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
        JSON.stringify([]),
      );

    if (kind === 'dm') {
      this.db
        .prepare(`INSERT OR IGNORE INTO session_members (session_key, user_id, role, created_at) VALUES (?, ?, 'member', ?)`)
        .run(sessionKey, access.userId, now);
    }

    return { session, created: true };
  }

  listSessions(opts: { userId: string; isAdmin: boolean; allowedAgents: string[]; limit: number; activeMinutes?: number; kind?: 'dm' | 'group' | 'channel' }): {
    sessions: Omit<Session, 'participants' | 'createdAt'>[];
    count: number;
  } {
    const where: string[] = [];
    const params: unknown[] = [];

    if (!opts.isAdmin) {
      if (opts.allowedAgents.length === 0) {
        return { sessions: [], count: 0 };
      }
      const agentWheres = opts.allowedAgents.map(() => `key LIKE ?`).join(' OR ');
      where.push(`(${agentWheres})`);
      for (const a of opts.allowedAgents) params.push(`agent:${a}:%`);
      // For DM sessions, require membership; non-DM sessions are visible to all users on that agent.
      where.push(`(kind != 'dm' OR key IN (SELECT session_key FROM session_members WHERE user_id = ?))`);
      params.push(opts.userId);
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

  getSession(sessionKey: string, access: { userId: string; isAdmin: boolean; allowedAgents: string[] }): (Omit<Session, 'participants'> & { participants: string[] }) | undefined {
    const row = this.db
      .prepare(
        `SELECT key, session_id as sessionId, kind, channel, display_name as displayName, created_at as createdAt, updated_at as updatedAt, model, total_tokens as totalTokens, context_tokens as contextTokens, transcript_path as transcriptPath, participants_json as participantsJson
         FROM sessions WHERE key = ?`,
      )
      .get(sessionKey) as any;
    if (!row) return undefined;
    if (!this.canAccessSession(sessionKey, access)) return undefined;
    const participants =
      row.kind === 'dm'
        ? ((this.db.prepare(`SELECT user_id as userId FROM session_members WHERE session_key = ?`).all(sessionKey) as any[]).map((r) => String(r.userId)))
        : [];
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

  deleteSession(sessionKey: string, access: { userId: string; isAdmin: boolean; allowedAgents: string[] }): { ok: true; deleted: { sessionKey: string; transcriptDeleted: boolean; messagesDeleted: number } } | null {
    const s = this.getSession(sessionKey, access);
    if (!s) return null;
    if (!access.isAdmin) return null;
    const abs = path.resolve(this.dataDir, s.transcriptPath);
    let transcriptDeleted = false;
    try {
      fs.unlinkSync(abs);
      transcriptDeleted = true;
    } catch {
      transcriptDeleted = false;
    }
    const delMsgs = this.db.prepare(`DELETE FROM room_messages WHERE session_key = ?`).run(sessionKey) as any;
    this.db.prepare(`DELETE FROM session_members WHERE session_key = ?`).run(sessionKey);
    this.db.prepare(`DELETE FROM sessions WHERE key = ?`).run(sessionKey);
    return { ok: true, deleted: { sessionKey, transcriptDeleted, messagesDeleted: delMsgs.changes ?? 0 } };
  }

  countSessions(): { total: number; active: number } {
    const totalRow = this.db.prepare(`SELECT COUNT(*) as n FROM sessions`).get() as { n: number };
    const activeRow = this.db.prepare(`SELECT COUNT(*) as n FROM sessions WHERE updated_at >= ?`).get(Date.now() - 60 * 60_000) as { n: number };
    return { total: totalRow.n ?? 0, active: activeRow.n ?? 0 };
  }

  // --- Room Messages

  appendRoomMessage(sessionKey: string, msg: ChatMessage, opts?: { runId?: string }): void {
    const nowMs = Date.now();
    this.db
      .prepare(
        `INSERT INTO room_messages (id, session_key, role, content, timestamp, created_at_ms, run_id, model, tokens_json, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        msg.id,
        sessionKey,
        msg.role,
        msg.content,
        msg.timestamp,
        nowMs,
        opts?.runId ?? null,
        msg.model ?? null,
        msg.tokens ? JSON.stringify(msg.tokens) : null,
        msg.metadata ? JSON.stringify(msg.metadata) : null,
      );
    this.db.prepare(`UPDATE sessions SET updated_at = ? WHERE key = ?`).run(nowMs, sessionKey);
  }

  getSessionHistory(
    sessionKey: string,
    opts: { userId: string; isAdmin: boolean; allowedAgents: string[]; limit: number; includeTools: boolean; before?: string },
  ): { messages: ChatMessage[]; hasMore: boolean; nextCursor?: string } | null {
    if (!this.canAccessSession(sessionKey, { userId: opts.userId, isAdmin: opts.isAdmin, allowedAgents: opts.allowedAgents })) return null;
    const sessionRow = this.db.prepare(`SELECT 1 as ok FROM sessions WHERE key = ?`).get(sessionKey) as any;
    if (!sessionRow?.ok) return null;

    let beforeMs: number | undefined;
    if (opts.before) {
      const row = this.db.prepare(`SELECT created_at_ms as ms FROM room_messages WHERE id = ? AND session_key = ?`).get(opts.before, sessionKey) as any;
      if (row?.ms && Number.isFinite(row.ms)) beforeMs = Number(row.ms);
    }

    const limit = Math.max(1, Math.min(1000, opts.limit));
    const rows = this.db
      .prepare(
        `SELECT id, role, content, timestamp, model, tokens_json as tokensJson, metadata_json as metadataJson, created_at_ms as createdAtMs
         FROM room_messages
         WHERE session_key = ?
           AND (? IS NULL OR created_at_ms < ?)
         ORDER BY created_at_ms DESC
         LIMIT ?`,
      )
      .all(sessionKey, beforeMs ?? null, beforeMs ?? null, limit + 1) as any[];

    const mapped = rows
      .map((r) => {
        const role = String(r.role) as ChatMessage['role'];
        if (!opts.includeTools && role === 'tool') return null;
        return {
          id: String(r.id),
          role,
          content: String(r.content),
          timestamp: String(r.timestamp),
          model: r.model ? String(r.model) : undefined,
          tokens: r.tokensJson ? (JSON.parse(String(r.tokensJson)) as any) : undefined,
          metadata: r.metadataJson ? (JSON.parse(String(r.metadataJson)) as any) : undefined,
        } satisfies ChatMessage;
      })
      .filter(Boolean) as ChatMessage[];

    const hasMore = mapped.length > limit;
    const page = mapped.slice(0, limit).reverse(); // chronological
    const nextCursor = hasMore ? mapped[limit - 1]?.id : undefined;
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
