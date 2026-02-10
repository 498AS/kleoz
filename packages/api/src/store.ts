import { Database } from 'bun:sqlite';
import bcrypt from 'bcryptjs';

import type { JwtRole } from './jwt.js';
import type { KleozConfig } from './config.js';

export type DbUserRow = {
  id: string;
  username: string;
  password_hash: string;
  agent_id: string;
  role: JwtRole;
  created_at: number;
};

export type DbUploadRow = {
  id: string;
  filename: string;
  mime_type: string;
  size: number;
  path: string;
  created_at: number;
  expires_at: number;
};

export type DbLocalMessageRow = {
  id: string;
  session_key: string;
  role: 'user' | 'assistant' | 'tool';
  content: string;
  timestamp: number;
  metadata_json: string | null;
  model: string | null;
  tokens_json: string | null;
};

export class SqliteStore {
  readonly db: Database;

  constructor(private readonly cfg: KleozConfig) {
    this.db = new Database(cfg.databasePath);

    // Pragmas safe enough for local single-node use.
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA synchronous = NORMAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
  }

  init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS uploads (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL,
        path TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);

    // Messages that are "local to kleoz" (e.g. messages that should not invoke the agent).
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS local_messages (
        id TEXT PRIMARY KEY,
        session_key TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        metadata_json TEXT,
        model TEXT,
        tokens_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_local_messages_session_ts ON local_messages(session_key, timestamp);
    `);

    this.ensureAdminUser();
  }

  isConnected(): boolean {
    try {
      this.db.prepare('SELECT 1').get();
      return true;
    } catch {
      return false;
    }
  }

  ensureAdminUser(): void {
    const count = (this.db.prepare('SELECT COUNT(*) as n FROM users').get() as { n: number } | null)?.n ?? 0;
    if (count > 0) return;

    const id = crypto.randomUUID();
    const now = Date.now();
    const hash = bcrypt.hashSync(this.cfg.adminPassword, 10);
    this.db
      .prepare(
        'INSERT INTO users (id, username, password_hash, agent_id, role, created_at) VALUES ($id, $username, $hash, $agent, $role, $createdAt)',
      )
      .run({
        $id: id,
        $username: this.cfg.adminUsername,
        $hash: hash,
        $agent: 'main',
        $role: 'admin',
        $createdAt: now,
      });
  }

  findUserByUsername(username: string): DbUserRow | null {
    const row = this.db
      .prepare('SELECT id, username, password_hash, agent_id, role, created_at FROM users WHERE username = ?')
      .get(username) as DbUserRow | null;
    return row ?? null;
  }

  findUserById(id: string): DbUserRow | null {
    const row = this.db
      .prepare('SELECT id, username, password_hash, agent_id, role, created_at FROM users WHERE id = ?')
      .get(id) as DbUserRow | null;
    return row ?? null;
  }

  listUsers(): Array<Omit<DbUserRow, 'password_hash'>> {
    const rows = this.db
      .prepare('SELECT id, username, agent_id, role, created_at FROM users ORDER BY created_at DESC')
      .all() as Array<Omit<DbUserRow, 'password_hash'>> | null;
    return rows ?? [];
  }

  createUser(input: { username: string; password: string; agentId: string; role: JwtRole }): DbUserRow {
    const id = crypto.randomUUID();
    const now = Date.now();
    const hash = bcrypt.hashSync(input.password, 10);
    this.db
      .prepare(
        'INSERT INTO users (id, username, password_hash, agent_id, role, created_at) VALUES ($id, $username, $hash, $agent, $role, $createdAt)',
      )
      .run({
        $id: id,
        $username: input.username,
        $hash: hash,
        $agent: input.agentId,
        $role: input.role,
        $createdAt: now,
      });

    return {
      id,
      username: input.username,
      password_hash: hash,
      agent_id: input.agentId,
      role: input.role,
      created_at: now,
    };
  }

  updateUser(
    userId: string,
    patch: { username?: string; password?: string; agentId?: string; role?: JwtRole },
  ): DbUserRow | null {
    const current = this.findUserById(userId);
    if (!current) return null;

    const nextUsername = patch.username ?? current.username;
    const nextAgent = patch.agentId ?? current.agent_id;
    const nextRole = patch.role ?? current.role;
    const nextHash = patch.password ? bcrypt.hashSync(patch.password, 10) : current.password_hash;

    this.db
      .prepare(
        'UPDATE users SET username = $username, password_hash = $hash, agent_id = $agent, role = $role WHERE id = $id',
      )
      .run({
        $id: userId,
        $username: nextUsername,
        $hash: nextHash,
        $agent: nextAgent,
        $role: nextRole,
      });

    return {
      id: userId,
      username: nextUsername,
      password_hash: nextHash,
      agent_id: nextAgent,
      role: nextRole,
      created_at: current.created_at,
    };
  }

  deleteUser(userId: string): boolean {
    const res = this.db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    return (res.changes ?? 0) > 0;
  }

  createUpload(row: DbUploadRow): void {
    this.db
      .prepare(
        'INSERT INTO uploads (id, filename, mime_type, size, path, created_at, expires_at) VALUES ($id, $filename, $mime, $size, $path, $createdAt, $expiresAt)',
      )
      .run({
        $id: row.id,
        $filename: row.filename,
        $mime: row.mime_type,
        $size: row.size,
        $path: row.path,
        $createdAt: row.created_at,
        $expiresAt: row.expires_at,
      });
  }

  getUpload(id: string): DbUploadRow | null {
    const row = this.db
      .prepare('SELECT id, filename, mime_type, size, path, created_at, expires_at FROM uploads WHERE id = ?')
      .get(id) as DbUploadRow | null;
    if (!row) return null;
    if (row.expires_at < Date.now()) return null;
    return row;
  }

  putLocalMessage(row: DbLocalMessageRow): void {
    this.db
      .prepare(
        'INSERT OR REPLACE INTO local_messages (id, session_key, role, content, timestamp, metadata_json, model, tokens_json) VALUES ($id, $key, $role, $content, $ts, $meta, $model, $tokens)',
      )
      .run({
        $id: row.id,
        $key: row.session_key,
        $role: row.role,
        $content: row.content,
        $ts: row.timestamp,
        $meta: row.metadata_json,
        $model: row.model,
        $tokens: row.tokens_json,
      });
  }

  listLocalMessages(sessionKey: string, limit: number): DbLocalMessageRow[] {
    const rows = this.db
      .prepare(
        'SELECT id, session_key, role, content, timestamp, metadata_json, model, tokens_json FROM local_messages WHERE session_key = ? ORDER BY timestamp DESC LIMIT ?',
      )
      .all(sessionKey, limit) as DbLocalMessageRow[] | null;
    return rows ?? [];
  }
}
