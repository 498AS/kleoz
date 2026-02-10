import { Hono } from 'hono';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import type { Context, Next } from 'hono';
import type { WebSocketServer } from 'ws';
import { SQLiteStore } from './store.js';
import { revokeToken, signToken, verifyToken } from './auth.js';
import type { ChatMessage, JwtClaims, Variables } from './types.js';
import { RealtimeHub } from './realtime.js';
import { config } from './config.js';
import { createRateLimiter } from './rateLimit.js';

function nowIso(): string {
  return new Date().toISOString();
}

function apiError(code: string, message: string, details?: Record<string, unknown>) {
  return { error: { code, message, ...(details ? { details } : {}) } };
}

function permissionsFor(role: JwtClaims['role']) {
  return {
    canSendMessages: true,
    canViewAllSessions: role === 'admin',
    canManageUsers: role === 'admin',
  };
}

export function buildApp(store = new SQLiteStore(), hub = new RealtimeHub()) {
  const app = new Hono<{ Variables: Variables }>();

  app.onError((err, c) => {
    if (err instanceof z.ZodError) {
      return c.json(apiError('INVALID_REQUEST', 'Invalid request', { issues: err.issues }), 400);
    }
    // Avoid leaking internal errors.
    return c.json(apiError('INVALID_REQUEST', 'Request failed'), 500);
  });

  const loginSchema = z.object({ username: z.string(), password: z.string() });
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
  const sendSchema = z.object({
    sessionKey: z.string().min(1),
    message: z.string().min(1),
    attachments: z
      .array(
        z.object({
          type: z.enum(['image', 'file', 'audio']),
          data: z.string(),
          filename: z.string(),
          mimeType: z.string(),
        }),
      )
      .optional(),
  });

  const auth = async (c: Context, next: Next) => {
    const authorization = c.req.header('authorization');
    if (!authorization?.startsWith('Bearer ')) return c.json(apiError('UNAUTHORIZED', 'Unauthorized'), 401);
    try {
      const claims = await verifyToken(authorization.replace('Bearer ', ''));
      c.set('user', claims);
      await next();
    } catch {
      return c.json(apiError('UNAUTHORIZED', 'Invalid token'), 401);
    }
  };

  const onlyAdmin = async (c: Context, next: Next) => {
    if ((c.get('user') as JwtClaims).role !== 'admin') return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);
    await next();
  };

  const rateLimit = createRateLimiter();
  const rlKey = (c: Context) => {
    const authz = c.req.header('authorization');
    if (authz?.startsWith('Bearer ')) {
      return `bearer:${authz.slice('Bearer '.length)}`;
    }
    return `ip:${c.req.header('x-forwarded-for') ?? c.req.header('x-real-ip') ?? 'unknown'}`;
  };

  app.get('/api/health', (c) => {
    return c.json({
      status: 'ok',
      timestamp: nowIso(),
      gateway: { connected: false, latency: undefined },
      database: { connected: true },
    });
  });

  app.post('/api/auth/login', rateLimit({ key: rlKey, points: config.rateLimits.login.points, windowSeconds: config.rateLimits.login.windowSeconds }), async (c) => {
    const parsed = loginSchema.parse(await c.req.json());
    const user = store.findUserByUsername(parsed.username);
    if (!user || !bcrypt.compareSync(parsed.password, user.passwordHash)) {
      return c.json(apiError('UNAUTHORIZED', 'Invalid credentials'), 401);
    }
    store.touchUserLogin(user.id);
    const token = await signToken({ sub: user.id, username: user.username, role: user.role, agentId: user.agentId, jti: crypto.randomUUID() });
    return c.json({
      token,
      expiresAt: new Date(Date.now() + config.auth.jwtExpiresInSeconds * 1000).toISOString(),
      user: { id: user.id, username: user.username, role: user.role, agentId: user.agentId, createdAt: new Date(user.createdAt).toISOString() },
    });
  });

  app.post('/api/auth/logout', auth, async (c) => {
    const authorization = c.req.header('authorization')!;
    await revokeToken(authorization.replace('Bearer ', ''));
    return c.json({ ok: true });
  });

  app.get('/api/auth/me', auth, (c) => {
    const user = c.get('user') as JwtClaims;
    return c.json({ id: user.sub, username: user.username, agentId: user.agentId, role: user.role, permissions: permissionsFor(user.role) });
  });

  app.get('/api/users', auth, onlyAdmin, (c) => {
    const users = store.listUsers().map((u) => ({ id: u.id, username: u.username, role: u.role, agentId: u.agentId, createdAt: new Date(u.createdAt).toISOString() }));
    return c.json({ users });
  });

  app.post('/api/users', auth, onlyAdmin, async (c) => {
    const parsed = userCreateSchema.parse(await c.req.json());
    let user;
    try {
      user = store.createUser(parsed);
    } catch (e) {
      return c.json(apiError('INVALID_REQUEST', 'User could not be created'), 400);
    }
    return c.json({ id: user.id, username: user.username, role: user.role, agentId: user.agentId, createdAt: new Date(user.createdAt).toISOString() }, 201);
  });

  app.put('/api/users/:userId', auth, onlyAdmin, async (c) => {
    const parsed = userUpdateSchema.parse(await c.req.json());
    const userId = c.req.param('userId');
    const updated = store.updateUser(userId, parsed);
    if (!updated) return c.json(apiError('NOT_FOUND', 'User not found'), 404);
    return c.json({ ok: true });
  });

  app.delete('/api/users/:userId', auth, onlyAdmin, (c) => {
    const userId = c.req.param('userId');
    const ok = store.deleteUser(userId);
    if (!ok) return c.json(apiError('NOT_FOUND', 'User not found'), 404);
    return c.json({ ok: true });
  });

  app.get('/api/agents', auth, (c) => {
    const user = c.get('user') as JwtClaims;
    const allowed = store.listAllowedAgents({ userId: user.sub, isAdmin: user.role === 'admin', fallbackAgentId: user.agentId });
    return c.json({ agents: allowed.map((id) => ({ id, name: id })) });
  });

  app.get('/api/agents/:agentId/config', auth, onlyAdmin, (c) => {
    const agentId = c.req.param('agentId');
    if (!config.agents.allowed.includes(agentId)) return c.json(apiError('NOT_FOUND', 'Agent not found'), 404);
    return c.json({ id: agentId, allowed: true, gateway: { url: config.gateway.url } });
  });

  app.get('/api/sessions', auth, (c) => {
    const user = c.get('user') as JwtClaims;
    const allowedAgents = store.listAllowedAgents({ userId: user.sub, isAdmin: user.role === 'admin', fallbackAgentId: user.agentId });
    const limit = Number(c.req.query('limit') ?? 50);
    const activeMinutes = c.req.query('activeMinutes') ? Number(c.req.query('activeMinutes')) : undefined;
    const kind = c.req.query('kind') as string | undefined;
    const { sessions, count } = store.listSessions({
      userId: user.sub,
      isAdmin: user.role === 'admin',
      allowedAgents,
      limit: Number.isFinite(limit) ? limit : 50,
      activeMinutes: activeMinutes && Number.isFinite(activeMinutes) ? activeMinutes : undefined,
      kind: kind && ['dm', 'group', 'channel'].includes(kind) ? (kind as any) : undefined,
    });
    // Return session summaries (no transcript path/participants).
    return c.json({
      count,
      sessions: sessions.map((s: any) => ({
        key: s.key,
        sessionId: s.sessionId,
        kind: s.kind,
        channel: s.channel,
        displayName: s.displayName,
        updatedAt: s.updatedAt,
        model: s.model,
        totalTokens: s.totalTokens,
        contextTokens: s.contextTokens,
        origin: s.origin,
        status: s.status,
      })),
    });
  });

  app.get('/api/sessions/:sessionKey', auth, (c) => {
    const user = c.get('user') as JwtClaims;
    const allowedAgents = store.listAllowedAgents({ userId: user.sub, isAdmin: user.role === 'admin', fallbackAgentId: user.agentId });
    const key = decodeURIComponent(c.req.param('sessionKey'));
    const session = store.getSession(key, { userId: user.sub, isAdmin: user.role === 'admin', allowedAgents });
    if (!session) return c.json(apiError('NOT_FOUND', 'Session not found'), 404);
    return c.json({
      key: session.key,
      sessionId: session.sessionId,
      kind: session.kind,
      channel: session.channel,
      displayName: session.displayName,
      updatedAt: session.updatedAt,
      model: session.model,
      totalTokens: session.totalTokens,
      inputTokens: undefined,
      outputTokens: undefined,
      contextTokens: session.contextTokens,
      abortedLastRun: false,
      transcriptPath: session.transcriptPath,
    });
  });

  app.get('/api/sessions/:sessionKey/history', auth, (c) => {
    const user = c.get('user') as JwtClaims;
    const allowedAgents = store.listAllowedAgents({ userId: user.sub, isAdmin: user.role === 'admin', fallbackAgentId: user.agentId });
    const key = decodeURIComponent(c.req.param('sessionKey'));
    const limit = Number(c.req.query('limit') ?? 100);
    const includeTools = (c.req.query('includeTools') ?? 'false') === 'true';
    const before = c.req.query('before') ?? undefined;

    const out = store.getSessionHistory(key, {
      userId: user.sub,
      isAdmin: user.role === 'admin',
      allowedAgents,
      limit: Number.isFinite(limit) ? limit : 100,
      includeTools,
      before,
    });
    if (!out) return c.json(apiError('NOT_FOUND', 'Session not found'), 404);
    return c.json(out);
  });

  app.delete('/api/sessions/:sessionKey', auth, onlyAdmin, (c) => {
    const user = c.get('user') as JwtClaims;
    const allowedAgents = store.listAllowedAgents({ userId: user.sub, isAdmin: true, fallbackAgentId: user.agentId });
    const key = decodeURIComponent(c.req.param('sessionKey'));
    const out = store.deleteSession(key, { userId: user.sub, isAdmin: true, allowedAgents });
    if (!out) return c.json(apiError('NOT_FOUND', 'Session not found'), 404);
    hub.emitToSession(key, { type: 'session.deleted', sessionKey: key });
    return c.json(out);
  });

  app.post('/api/messages/send', auth, rateLimit({ key: rlKey, points: config.rateLimits.send.points, windowSeconds: config.rateLimits.send.windowSeconds }), async (c) => {
    const parsed = sendSchema.parse(await c.req.json());
    const user = c.get('user') as JwtClaims;
    const sessionKey = parsed.sessionKey;
    const allowedAgents = store.listAllowedAgents({ userId: user.sub, isAdmin: user.role === 'admin', fallbackAgentId: user.agentId });
    const ensured = store.ensureSession(sessionKey, { userId: user.sub, isAdmin: user.role === 'admin', allowedAgents });
    if (!ensured) return c.json(apiError('FORBIDDEN', 'Forbidden'), 403);
    const session = ensured.session;
    const agentId = /^agent:([^:]+):/.exec(sessionKey)?.[1];

    if (ensured.created && session.kind !== 'dm' && agentId) {
      hub.emitToAgent(agentId, {
        type: 'session.created',
        session: {
          key: session.key,
          sessionId: session.sessionId,
          kind: session.kind,
          channel: session.channel ?? 'unknown',
          displayName: session.displayName,
          updatedAt: session.updatedAt,
          model: session.model,
          totalTokens: session.totalTokens,
          contextTokens: session.contextTokens,
        },
      });
    }

    const runId = crypto.randomUUID();
    const now = nowIso();
    const userMsg: ChatMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      content: parsed.message,
      timestamp: now,
      metadata: { username: user.username, userId: user.sub, attachments: parsed.attachments ?? [] },
    };
    store.appendRoomMessage(sessionKey, userMsg, { runId });
    hub.emitToSession(sessionKey, { type: 'message.complete', sessionKey, runId, message: userMsg });
    hub.emitToSession(sessionKey, { type: 'session.updated', sessionKey, changes: { updatedAt: Date.now() } });
    if (session.kind !== 'dm' && agentId) {
      hub.emitToAgent(agentId, { type: 'session.updated', sessionKey, changes: { updatedAt: Date.now() } });
    }

    const isDm = session.kind === 'dm';
    const mentionsAgent =
      isDm ||
      /@agent\b/i.test(parsed.message) ||
      (agentId ? new RegExp(`@${agentId}\\b`, 'i').test(parsed.message) : false);

    if (mentionsAgent) {
      const content = `Respuesta automática para: ${parsed.message.replace(/@agent/gi, '').trim()}`;
      // Simulated streaming: 2 deltas + complete.
      const mid = Math.max(1, Math.floor(content.length / 2));
      hub.emitToSession(sessionKey, { type: 'message.delta', sessionKey, runId, delta: { content: content.slice(0, mid) } });
      hub.emitToSession(sessionKey, { type: 'message.delta', sessionKey, runId, delta: { content: content.slice(mid) } });
      const msg: ChatMessage = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content,
        timestamp: nowIso(),
        model: 'mock',
        tokens: { input: undefined, output: undefined },
        metadata: { agentId: agentId ?? user.agentId },
      };
      store.appendRoomMessage(sessionKey, msg, { runId });
      hub.emitToSession(sessionKey, { type: 'message.complete', sessionKey, runId, message: msg });
    }

    return c.json({ ok: true, runId, status: 'accepted' });
  });

  app.post('/api/messages/upload', auth, rateLimit({ key: rlKey, points: config.rateLimits.upload.points, windowSeconds: config.rateLimits.upload.windowSeconds }), async (c) => {
    const body = await c.req.parseBody();
    const file = body['file'];
    if (!(file instanceof File)) return c.json(apiError('INVALID_REQUEST', 'Missing file'), 400);
    const out = await store.saveUpload(file);
    return c.json(out);
  });

  app.get('/api/uploads/:uploadId', async (c) => {
    const uploadId = c.req.param('uploadId');
    const out = store.getUploadPath(uploadId);
    if (!out) return c.json(apiError('NOT_FOUND', 'Upload not found'), 404);
    const { path, mimeType, size } = out;
    const data = await store.readUploadBytes(path);
    return new Response(data as unknown as BodyInit, {
      headers: {
        'content-type': mimeType,
        'content-length': String(size),
      },
    });
  });

  app.get('/api/presence', auth, (c) => {
    return c.json({ entries: hub.presenceEntries(), gatewayUptime: 0, timestamp: Date.now() });
  });

  const startedAt = Date.now();
  app.get('/api/status', auth, onlyAdmin, (c) => {
    const uptime = Math.floor(process.uptime());
    const sessions = store.countSessions();
    const users = store.countUsers();
    return c.json({
      version: config.version,
      uptime,
      gateway: { url: config.gateway.url, connected: false, protocol: undefined },
      sessions: { active: sessions.active, total: sessions.total },
      users: { online: hub.onlineUserCount(), total: users },
      startedAt,
    });
  });

  return { app, store, hub };
}

export function attachWsHandlers(wss: WebSocketServer, hub: RealtimeHub) {
  wss.on('connection', (ws, claims: JwtClaims) => {
    hub.register(ws, { userId: claims.sub, username: claims.username, agentId: claims.agentId });
    ws.on('message', (raw) => {
      try {
        hub.noteInput(ws);
        const data = JSON.parse(raw.toString()) as { type?: string; sessionKeys?: string[]; token?: string; client?: { instanceId?: string; version?: string; platform?: string; mode?: string } };
        if (data.type === 'connect' && data.client) hub.updateClient(ws, data.client);
        if (data.type === 'subscribe' || data.type === 'sessions.subscribe') hub.setSubscriptions(ws, data.sessionKeys ?? []);
        if (data.type === 'unsubscribe') hub.removeSubscriptions(ws, data.sessionKeys ?? []);
        if (data.type === 'subscribe.presence') hub.enablePresence(ws);
      } catch {
        ws.send(JSON.stringify(apiError('INVALID_REQUEST', 'Malformed message')));
      }
    });
    ws.on('close', () => hub.unregister(ws));
    ws.send(JSON.stringify({ type: 'connected', wsSessionId: crypto.randomUUID() }));
  });
}
