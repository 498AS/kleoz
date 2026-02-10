import { Hono } from 'hono';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import type { Context, Next } from 'hono';
import type { WebSocketServer } from 'ws';
import { InMemoryStore } from './store.js';
import { signToken, verifyToken } from './auth.js';
import type { JwtClaims } from './types.js';
import { RealtimeHub } from './realtime.js';

export function buildApp(store = new InMemoryStore(), hub = new RealtimeHub()) {
  const app = new Hono();

  const loginSchema = z.object({ username: z.string(), password: z.string() });
  const userSchema = z.object({ username: z.string(), password: z.string().min(8), role: z.enum(['admin', 'user']), agentId: z.string() });
  const sendSchema = z.object({ sessionKey: z.string(), message: z.string().min(1), participants: z.array(z.string()).default([]) });

  const auth = async (c: Context, next: Next) => {
    const authorization = c.req.header('authorization');
    if (!authorization?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401);
    try {
      const claims = await verifyToken(authorization.replace('Bearer ', ''));
      c.set('user', claims);
      await next();
    } catch {
      return c.json({ error: 'Invalid token' }, 401);
    }
  };

  const onlyAdmin = async (c: Context, next: Next) => {
    if ((c.get('user') as JwtClaims).role !== 'admin') return c.json({ error: 'Forbidden' }, 403);
    await next();
  };

  app.get('/api/health', (c) => c.json({ ok: true }));

  app.post('/api/auth/login', async (c) => {
    const parsed = loginSchema.parse(await c.req.json());
    const user = store.findUserByUsername(parsed.username);
    if (!user || !bcrypt.compareSync(parsed.password, user.passwordHash)) return c.json({ error: 'Invalid credentials' }, 401);
    const token = await signToken({ sub: user.id, username: user.username, role: user.role, agentId: user.agentId });
    return c.json({ token, user: { id: user.id, username: user.username, role: user.role, agentId: user.agentId } });
  });

  app.get('/api/auth/me', auth, (c) => c.json({ user: c.get('user') }));

  app.post('/api/users', auth, onlyAdmin, async (c) => {
    const parsed = userSchema.parse(await c.req.json());
    const user = store.createUser(parsed);
    return c.json({ id: user.id, username: user.username, role: user.role, agentId: user.agentId }, 201);
  });

  app.get('/api/sessions', auth, (c) => {
    const user = c.get('user') as JwtClaims;
    const all = Array.from(store.sessions.values());
    return c.json({ sessions: user.role === 'admin' ? all : all.filter((s) => s.participants.includes(user.sub)) });
  });

  app.get('/api/sessions/:sessionKey/history', auth, (c) => {
    const session = store.sessions.get(decodeURIComponent(c.req.param('sessionKey')));
    if (!session) return c.json({ messages: [] });
    const user = c.get('user') as JwtClaims;
    if (user.role !== 'admin' && !session.participants.includes(user.sub)) return c.json({ error: 'Forbidden' }, 403);
    return c.json({ messages: session.messages });
  });

  app.post('/api/messages/send', auth, async (c) => {
    const parsed = sendSchema.parse(await c.req.json());
    const user = c.get('user') as JwtClaims;
    const session = store.upsertSession(parsed.sessionKey, parsed.participants.length > 0 ? parsed.participants : [user.sub]);
    if (user.role !== 'admin' && !session.participants.includes(user.sub)) return c.json({ error: 'Forbidden' }, 403);
    const mentionsAgent = /@agent\b/i.test(parsed.message);
    const humanMsg = store.appendMessage(parsed.sessionKey, { sessionKey: parsed.sessionKey, sender: user.username, senderUserId: user.sub, body: parsed.message, mentionsAgent });
    hub.emitToSession(parsed.sessionKey, { type: 'message.complete', sessionKey: parsed.sessionKey, message: humanMsg });
    if (mentionsAgent) {
      const agentMsg = store.appendMessage(parsed.sessionKey, {
        sessionKey: parsed.sessionKey,
        sender: 'agent',
        senderUserId: 'agent',
        body: `Respuesta automática para: ${parsed.message.replace(/@agent/gi, '').trim()}`,
        mentionsAgent: false,
      });
      hub.emitToSession(parsed.sessionKey, { type: 'message.complete', sessionKey: parsed.sessionKey, message: agentMsg });
    }
    return c.json({ queued: true });
  });

  app.get('/api/presence', auth, (c) => c.json({ ok: true }));

  return { app, store, hub };
}

export function attachWsHandlers(wss: WebSocketServer, hub: RealtimeHub) {
  wss.on('connection', (ws, claims: JwtClaims) => {
    hub.register(ws, { userId: claims.sub, username: claims.username, agentId: claims.agentId });
    ws.on('message', (raw) => {
      try {
        const data = JSON.parse(raw.toString()) as { type?: string; sessionKeys?: string[] };
        if (data.type === 'sessions.subscribe') hub.setSubscriptions(ws, data.sessionKeys ?? []);
      } catch {
        ws.send(JSON.stringify({ type: 'error', error: 'Malformed message' }));
      }
    });
    ws.on('close', () => hub.unregister(ws));
  });
}
