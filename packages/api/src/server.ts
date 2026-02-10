import { Hono } from 'hono';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import type { ServerWebSocket } from 'bun';

import type {
  ApiErrorCode,
  ApiErrorResponse,
  AuthLoginRequest,
  AuthLoginResponse,
  AuthLogoutResponse,
  ChatMessage,
  HealthResponse,
  MessagesSendRequest,
  MessagesSendResponse,
  MessagesUploadResponse,
  PresenceEntry,
  SessionsDeleteResponse,
  SessionsHistoryResponse,
  SessionsListResponse,
  SessionDetail,
  SessionSummary,
  StatusResponse,
  UserMe,
  UserPublic,
  WsClientMessage,
  WsServerEvent,
} from '@kleoz/contracts';

import { computeExpiresAtIso, signToken, verifyToken } from './auth.js';
import type { KleozConfig } from './config.js';
import type { JwtClaims } from './jwt.js';
import { RealtimeHub } from './realtime.js';
import { SqliteStore } from './store.js';
export type GatewayLike = {
  isConnected: () => boolean;
  getLatencyMs: () => number | undefined;
  rpc: <TPayload = unknown>(method: string, params?: unknown, timeoutMs?: number) => Promise<TPayload>;
};

type Variables = { user: JwtClaims };

function apiError(code: ApiErrorCode, message: string, details?: Record<string, unknown>): ApiErrorResponse {
  return { error: { code, message, details } };
}

function toUserPublic(row: { id: string; username: string; agent_id: string; role: string; created_at: number }): UserPublic {
  return {
    id: row.id,
    username: row.username,
    agentId: row.agent_id,
    role: row.role === 'admin' ? 'admin' : 'user',
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function permissionsFromClaims(claims: JwtClaims): UserMe['permissions'] {
  const isAdmin = claims.role === 'admin';
  return {
    canSendMessages: true,
    canViewAllSessions: isAdmin,
    canManageUsers: isAdmin,
  };
}

function isSessionAllowedForUser(sessionKey: string, claims: JwtClaims): boolean {
  if (claims.role === 'admin') return true;
  return sessionKey.startsWith(`agent:${claims.agentId}:`);
}

function isDmSession(sessionKey: string): boolean {
  // Per docs: contains ":dm:" segments for DM keys.
  return sessionKey.includes(':dm:');
}

function shouldInvokeAgent(sessionKey: string, text: string, claims: JwtClaims): boolean {
  if (isDmSession(sessionKey)) return true;
  // Shared/group: require mention.
  const lower = text.toLowerCase();
  if (/\B@agent\b/i.test(text)) return true;
  if (claims.agentId && lower.includes(`@${claims.agentId.toLowerCase()}`)) return true;
  return false;
}

function normalizeChatMessage(raw: any): ChatMessage | null {
  const id = typeof raw?.id === 'string' && raw.id ? raw.id : crypto.randomUUID();
  const role = raw?.role === 'assistant' || raw?.role === 'tool' ? raw.role : 'user';
  const content = typeof raw?.content === 'string' ? raw.content : typeof raw?.body === 'string' ? raw.body : '';
  if (!content) return null;
  const tsRaw = raw?.timestamp ?? raw?.ts ?? raw?.createdAt ?? raw?.created_at;
  const timestamp =
    typeof tsRaw === 'string'
      ? tsRaw
      : typeof tsRaw === 'number'
        ? new Date(tsRaw).toISOString()
        : new Date().toISOString();
  const model = typeof raw?.model === 'string' ? raw.model : undefined;
  const tokens =
    raw?.tokens && typeof raw.tokens === 'object'
      ? {
          input: typeof raw.tokens.input === 'number' ? raw.tokens.input : undefined,
          output: typeof raw.tokens.output === 'number' ? raw.tokens.output : undefined,
        }
      : undefined;
  const metadata = raw?.metadata && typeof raw.metadata === 'object' ? (raw.metadata as Record<string, unknown>) : undefined;
  return { id, role, content, timestamp, model, tokens, metadata };
}

function normalizeSessionSummary(raw: any): SessionSummary | null {
  const key = typeof raw?.key === 'string' ? raw.key : '';
  if (!key) return null;
  const sessionId = typeof raw?.sessionId === 'string' ? raw.sessionId : typeof raw?.session_id === 'string' ? raw.session_id : key;
  const kind: SessionSummary['kind'] = key.includes(':dm:') ? 'dm' : key.includes(':group:') ? 'group' : 'channel';
  const channel = typeof raw?.channel === 'string' ? raw.channel : 'openclaw';
  const updatedAt = typeof raw?.updatedAt === 'number' ? raw.updatedAt : typeof raw?.updated_at === 'number' ? raw.updated_at : Date.now();
  const displayName = typeof raw?.displayName === 'string' ? raw.displayName : typeof raw?.label === 'string' ? raw.label : undefined;
  const model = typeof raw?.model === 'string' ? raw.model : undefined;
  const totalTokens = typeof raw?.totalTokens === 'number' ? raw.totalTokens : undefined;
  const contextTokens = typeof raw?.contextTokens === 'number' ? raw.contextTokens : undefined;
  const origin = raw?.origin && typeof raw.origin === 'object' ? (raw.origin as any) : undefined;
  const status = raw?.status === 'thinking' || raw?.status === 'typing' ? raw.status : 'idle';
  return { key, sessionId, kind, channel, displayName, updatedAt, model, totalTokens, contextTokens, origin, status };
}

export function buildApp(args: {
  cfg: KleozConfig;
  store: SqliteStore;
  hub: RealtimeHub;
  gateway: GatewayLike;
}) {
  const { cfg, store, hub, gateway } = args;
  const app = new Hono<{ Variables: Variables }>();

  const loginSchema = z.object({ username: z.string().min(1), password: z.string().min(1) } satisfies Record<keyof AuthLoginRequest, any>);
  const sendSchema = z.object({
    sessionKey: z.string().min(1),
    message: z.string().min(1),
    attachments: z
      .array(
        z.object({
          type: z.enum(['image', 'file', 'audio']),
          data: z.string().min(1),
          filename: z.string().min(1),
          mimeType: z.string().min(1),
        }),
      )
      .optional(),
  } satisfies Record<keyof MessagesSendRequest, any>);

  const userCreateSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(8),
    role: z.enum(['admin', 'user']),
    agentId: z.string().min(1),
  });

  const userUpdateSchema = z.object({
    username: z.string().min(1).optional(),
    password: z.string().min(8).optional(),
    role: z.enum(['admin', 'user']).optional(),
    agentId: z.string().min(1).optional(),
  });

  const auth = async (c: any, next: any) => {
    const authorization = c.req.header('authorization');
    if (!authorization?.startsWith('Bearer ')) {
      return c.json(apiError('UNAUTHORIZED', 'Unauthorized'), 401);
    }
    try {
      const claims = await verifyToken(cfg, authorization.replace('Bearer ', ''));
      c.set('user', claims);
      return await next();
    } catch {
      return c.json(apiError('UNAUTHORIZED', 'Invalid token'), 401);
    }
  };

  const onlyAdmin = async (c: any, next: any) => {
    const user = c.get('user') as JwtClaims;
    if (user.role !== 'admin') return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);
    return await next();
  };

  app.get('/api/health', (c) => {
    const out: HealthResponse = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      gateway: { connected: gateway.isConnected(), latency: gateway.getLatencyMs() },
      database: { connected: store.isConnected() },
    };
    return c.json(out);
  });

  app.get('/api/status', auth, (c) => {
    const out: StatusResponse = {
      version: '0.1.0',
      uptime: Math.floor(process.uptime()),
      gateway: { url: cfg.gateway.url, connected: gateway.isConnected(), protocol: cfg.gateway.maxProtocol },
      sessions: { active: 0, total: 0 },
      users: { online: 0, total: store.listUsers().length },
    };
    return c.json(out);
  });

  app.post('/api/auth/login', async (c) => {
    let body: unknown = null;
    try {
      body = await c.req.json();
    } catch {
      body = null;
    }
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) return c.json(apiError('INVALID_REQUEST', 'Invalid request', { issues: parsed.error.issues }), 400);

    const userRow = store.findUserByUsername(parsed.data.username);
    if (!userRow) return c.json(apiError('UNAUTHORIZED', 'Invalid credentials'), 401);

    const ok = bcrypt.compareSync(parsed.data.password, userRow.password_hash);
    if (!ok) return c.json(apiError('UNAUTHORIZED', 'Invalid credentials'), 401);

    const claims: JwtClaims = {
      sub: userRow.id,
      username: userRow.username,
      role: userRow.role,
      agentId: userRow.agent_id,
    };

    const now = Date.now();
    const token = await signToken(cfg, claims);
    const out: AuthLoginResponse = {
      token,
      expiresAt: computeExpiresAtIso(now, cfg.jwtExpiresIn),
      user: toUserPublic(userRow),
    };
    return c.json(out);
  });

  app.post('/api/auth/logout', auth, (c) => {
    const out: AuthLogoutResponse = { ok: true };
    return c.json(out);
  });

  app.get('/api/auth/me', auth, (c) => {
    const claims = c.get('user') as JwtClaims;
    const out: UserMe = {
      id: claims.sub,
      username: claims.username,
      agentId: claims.agentId,
      role: claims.role,
      permissions: permissionsFromClaims(claims),
    };
    return c.json(out);
  });

  app.get('/api/users', auth, onlyAdmin, (c) => {
    const users = store.listUsers().map((u) =>
      toUserPublic({
        ...u,
        password_hash: '',
      } as any),
    );
    return c.json({ users });
  });

  app.post('/api/users', auth, onlyAdmin, async (c) => {
    const parsed = userCreateSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json(apiError('INVALID_REQUEST', 'Invalid request', { issues: parsed.error.issues }), 400);
    try {
      const created = store.createUser(parsed.data);
      return c.json(toUserPublic(created as any), 201);
    } catch (e) {
      return c.json(apiError('INVALID_REQUEST', e instanceof Error ? e.message : 'Invalid request'), 400);
    }
  });

  app.put('/api/users/:userId', auth, onlyAdmin, async (c) => {
    const userId = String(c.req.param('userId') || '');
    const parsed = userUpdateSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json(apiError('INVALID_REQUEST', 'Invalid request', { issues: parsed.error.issues }), 400);
    const updated = store.updateUser(userId, parsed.data);
    if (!updated) return c.json(apiError('NOT_FOUND', 'User not found'), 404);
    return c.json(toUserPublic(updated as any));
  });

  app.delete('/api/users/:userId', auth, onlyAdmin, (c) => {
    const userId = String(c.req.param('userId') || '');
    const ok = store.deleteUser(userId);
    if (!ok) return c.json(apiError('NOT_FOUND', 'User not found'), 404);
    return c.json({ ok: true });
  });

  app.get('/api/sessions', auth, async (c) => {
    const claims = c.get('user') as JwtClaims;
    const limit = Number(c.req.query('limit') ?? '50') || 50;
    const activeMinutes = c.req.query('activeMinutes');
    const kind = c.req.query('kind');

    const payload = await gateway
      .rpc<{ sessions?: any[] }>('sessions.list', {
        limit,
        activeMinutes: activeMinutes ? Number(activeMinutes) : undefined,
        includeLastMessage: true,
        includeDerivedTitles: true,
      })
      .catch((e) => {
        return { sessions: [], __error: e instanceof Error ? e.message : String(e) } as any;
      });

    const raw = Array.isArray((payload as any).sessions) ? ((payload as any).sessions as any[]) : [];
    const normalized = raw.map(normalizeSessionSummary).filter((s): s is SessionSummary => Boolean(s));

    const filtered = normalized.filter((s) => isSessionAllowedForUser(s.key, claims));
    const kindFiltered =
      kind && (kind === 'dm' || kind === 'group' || kind === 'channel') ? filtered.filter((s) => s.kind === kind) : filtered;

    const out: SessionsListResponse = { count: kindFiltered.length, sessions: kindFiltered };
    return c.json(out);
  });

  app.get('/api/sessions/:sessionKey', auth, async (c) => {
    const claims = c.get('user') as JwtClaims;
    const sessionKey = decodeURIComponent(String(c.req.param('sessionKey') || ''));
    if (!isSessionAllowedForUser(sessionKey, claims)) return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);

    // Best-effort: resolve details by listing and matching.
    const payload = await gateway.rpc<{ sessions?: any[] }>('sessions.list', { limit: 200, includeDerivedTitles: true }).catch(() => ({
      sessions: [],
    }));
    const raw = Array.isArray((payload as any).sessions) ? ((payload as any).sessions as any[]) : [];
    const found = raw.find((s) => String(s?.key ?? '') === sessionKey);
    const summary = normalizeSessionSummary(found) ?? normalizeSessionSummary({ key: sessionKey });
    if (!summary) return c.json(apiError('NOT_FOUND', 'Session not found'), 404);

    const out: SessionDetail = {
      ...summary,
      inputTokens: typeof found?.inputTokens === 'number' ? found.inputTokens : undefined,
      outputTokens: typeof found?.outputTokens === 'number' ? found.outputTokens : undefined,
      abortedLastRun: Boolean(found?.abortedLastRun),
      transcriptPath: String(found?.transcriptPath ?? found?.transcript_path ?? ''),
    };
    return c.json(out);
  });

  app.get('/api/sessions/:sessionKey/history', auth, async (c) => {
    const claims = c.get('user') as JwtClaims;
    const sessionKey = decodeURIComponent(String(c.req.param('sessionKey') || ''));
    if (!isSessionAllowedForUser(sessionKey, claims)) return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);

    const limit = Number(c.req.query('limit') ?? '100') || 100;
    const includeTools = c.req.query('includeTools') === 'true';
    const before = c.req.query('before');

    const payload = await gateway
      .rpc<{ messages?: any[]; nextCursor?: string; hasMore?: boolean }>('chat.history', {
        sessionKey,
        limit,
        includeTools,
        before,
      })
      .catch(() => ({ messages: [], hasMore: false }));

    const rawMsgs = Array.isArray((payload as any).messages) ? ((payload as any).messages as any[]) : [];
    const gatewayMsgs = rawMsgs.map(normalizeChatMessage).filter((m): m is ChatMessage => Boolean(m));

    // Merge in local messages (for non-agent-invoking posts).
    const localRows = store.listLocalMessages(sessionKey, Math.max(limit, 200));
    const localMsgs = localRows
      .map((r) => {
        const meta = r.metadata_json ? (JSON.parse(r.metadata_json) as Record<string, unknown>) : undefined;
        const tokens = r.tokens_json ? (JSON.parse(r.tokens_json) as { input?: number; output?: number }) : undefined;
        return {
          id: r.id,
          role: r.role,
          content: r.content,
          timestamp: new Date(r.timestamp).toISOString(),
          metadata: meta,
          model: r.model ?? undefined,
          tokens,
        } satisfies ChatMessage;
      })
      .filter((m) => includeTools || m.role !== 'tool');

    const merged = [...gatewayMsgs, ...localMsgs]
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
      .slice(-limit);

    // De-dupe by id.
    const seen = new Set<string>();
    const deduped: ChatMessage[] = [];
    for (const m of merged) {
      if (seen.has(m.id)) continue;
      seen.add(m.id);
      deduped.push(m);
    }

    const out: SessionsHistoryResponse = {
      messages: deduped,
      hasMore: Boolean((payload as any).hasMore),
      nextCursor: typeof (payload as any).nextCursor === 'string' ? (payload as any).nextCursor : undefined,
    };
    return c.json(out);
  });

  app.delete('/api/sessions/:sessionKey', auth, async (c) => {
    const claims = c.get('user') as JwtClaims;
    const sessionKey = decodeURIComponent(String(c.req.param('sessionKey') || ''));
    if (!isSessionAllowedForUser(sessionKey, claims)) return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);
    await gateway.rpc('sessions.delete', { key: sessionKey }).catch(() => null);

    const out: SessionsDeleteResponse = { ok: true, deleted: { sessionKey, transcriptDeleted: true } };
    hub.broadcast({ type: 'session.deleted', sessionKey });
    return c.json(out);
  });

  app.post('/api/messages/send', auth, async (c) => {
    const claims = c.get('user') as JwtClaims;
    const parsed = sendSchema.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return c.json(apiError('INVALID_REQUEST', 'Invalid request', { issues: parsed.error.issues }), 400);
    const body = parsed.data;

    if (!isSessionAllowedForUser(body.sessionKey, claims)) return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);

    const userMsgId = crypto.randomUUID();
    const now = Date.now();
    const userMessage: ChatMessage = {
      id: userMsgId,
      role: 'user',
      content: body.message,
      timestamp: new Date(now).toISOString(),
      metadata: { from: claims.username, userId: claims.sub, source: 'kleoz' },
    };

    // Persist locally (so it doesn't vanish from history when we don't invoke the agent).
    store.putLocalMessage({
      id: userMsgId,
      session_key: body.sessionKey,
      role: 'user',
      content: body.message,
      timestamp: now,
      metadata_json: JSON.stringify(userMessage.metadata ?? {}),
      model: null,
      tokens_json: null,
    });

    // Broadcast immediately for multiplayer realtime.
    hub.emitToSession(body.sessionKey, {
      type: 'message.complete',
      sessionKey: body.sessionKey,
      runId: `local:${userMsgId}`,
      message: userMessage,
    });
    hub.broadcast({ type: 'session.updated', sessionKey: body.sessionKey, changes: { updatedAt: now } });

    const invoke = shouldInvokeAgent(body.sessionKey, body.message, claims);
    if (!invoke) {
      const out: MessagesSendResponse = { ok: true, runId: `local:${userMsgId}`, status: 'accepted' };
      return c.json(out);
    }

    hub.broadcast({ type: 'session.status', sessionKey: body.sessionKey, status: 'thinking' });

    try {
      const res = await gateway.rpc<{ runId: string }>('chat.send', {
        sessionKey: body.sessionKey,
        message: body.message,
        attachments: body.attachments,
        deliver: false,
        timeoutMs: 120_000,
        idempotencyKey: crypto.randomUUID(),
      });

      // Fallback: if the gateway doesn't stream events, poll a bit and emit the last assistant message.
      void (async () => {
        for (let i = 0; i < 6; i++) {
          await new Promise((r) => setTimeout(r, 400 * (i + 1)));
          const hist = await gateway
            .rpc<{ messages?: any[] }>('chat.history', { sessionKey: body.sessionKey, limit: 10 })
            .catch(() => ({ messages: [] }));
          const msgs = Array.isArray((hist as any).messages) ? ((hist as any).messages as any[]) : [];
          const last = msgs
            .map(normalizeChatMessage)
            .filter((m): m is ChatMessage => Boolean(m))
            .reverse()
            .find((m) => m.role === 'assistant');
          if (!last) continue;
          hub.emitToSession(body.sessionKey, { type: 'message.complete', sessionKey: body.sessionKey, runId: res.runId, message: last });
          break;
        }
      })();

      const out: MessagesSendResponse = { ok: true, runId: res.runId, status: 'accepted' };
      return c.json(out);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const ev: WsServerEvent = { type: 'error', sessionKey: body.sessionKey, error: { code: 'GATEWAY_UNAVAILABLE', message: msg } };
      hub.emitToSession(body.sessionKey, ev);
      return c.json(apiError('GATEWAY_UNAVAILABLE', msg), 503);
    } finally {
      hub.broadcast({ type: 'session.status', sessionKey: body.sessionKey, status: 'idle' });
    }
  });

  app.post('/api/messages/upload', auth, async (c) => {
    const form = await c.req.formData().catch(() => null);
    if (!form) return c.json(apiError('INVALID_REQUEST', 'Invalid form data'), 400);
    const file = form.get('file');
    if (!(file instanceof File)) return c.json(apiError('INVALID_REQUEST', 'file is required'), 400);
    if (file.size > cfg.maxUploadSizeBytes) return c.json(apiError('INVALID_REQUEST', 'File too large'), 400);

    const { mkdir } = await import('node:fs/promises');
    await mkdir(cfg.uploadsPath, { recursive: true });

    const id = crypto.randomUUID();
    const safeName = (file.name || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
    const path = `${cfg.uploadsPath}/${id}-${safeName}`;
    await Bun.write(path, file);

    const now = Date.now();
    const expiresAt = now + 60 * 60 * 1000;
    store.createUpload({
      id,
      filename: file.name || 'file',
      mime_type: file.type || 'application/octet-stream',
      size: file.size,
      path,
      created_at: now,
      expires_at: expiresAt,
    });

    const out: MessagesUploadResponse = {
      id,
      filename: file.name || 'file',
      mimeType: file.type || 'application/octet-stream',
      size: file.size,
      url: `/api/uploads/${id}`,
      expiresAt: new Date(expiresAt).toISOString(),
    };
    return c.json(out);
  });

  app.get('/api/uploads/:uploadId', auth, async (c) => {
    const uploadId = String(c.req.param('uploadId') || '');
    const row = store.getUpload(uploadId);
    if (!row) return c.json(apiError('NOT_FOUND', 'Upload not found'), 404);
    const f = Bun.file(row.path);
    if (!(await f.exists())) return c.json(apiError('NOT_FOUND', 'Upload not found'), 404);
    return new Response(f, {
      headers: {
        'content-type': row.mime_type,
        'content-disposition': `inline; filename="${row.filename.replace(/"/g, '')}"`,
      },
    });
  });

  app.get('/api/presence', auth, (c) => {
    // Best-effort: reflect web client presence. Gateway presence can be integrated later.
    const snap = hub.getPresenceSnapshot();
    const out = { entries: snap.entries, gatewayUptime: 0, timestamp: Date.now() };
    return c.json(out);
  });

  // WebSocket handler (Bun.serve websocket callbacks call into these).
  function onWsMessage(ws: ServerWebSocket<{ claims: JwtClaims }>, msg: string): void {
    let parsed: WsClientMessage | null = null;
    try {
      parsed = JSON.parse(msg) as WsClientMessage;
    } catch {
      return;
    }
    if (!parsed) return;

    if (parsed.type === 'connect') {
      // token is redundant (query param already authenticated) but keep contract compatibility.
      hub.updatePresenceFromClientInfo(ws, parsed.client ?? {});
      return;
    }
    if (parsed.type === 'subscribe') {
      hub.subscribe(ws, Array.isArray(parsed.sessionKeys) ? parsed.sessionKeys : []);
      return;
    }
    if (parsed.type === 'unsubscribe') {
      hub.unsubscribe(ws, Array.isArray(parsed.sessionKeys) ? parsed.sessionKeys : []);
      return;
    }
    if (parsed.type === 'subscribe.presence') {
      hub.subscribePresence(ws);
      return;
    }
    if (parsed.type === 'ping') {
      return;
    }
  }

  return { app, auth, onlyAdmin, hub, store, gateway, onWsMessage };
}
