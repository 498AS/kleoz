import path from 'node:path';

import type { ChatMessage, WsServerEvent } from '@kleoz/contracts';

import { loadConfig } from './config.js';
import { verifyToken } from './auth.js';
import { SqliteStore } from './store.js';
import { RealtimeHub } from './realtime.js';
import { buildApp } from './server.js';
import { OpenClawGatewayClient } from './openclaw/gatewayClient.js';

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
  return { id, role, content, timestamp, model: raw?.model, tokens: raw?.tokens, metadata: raw?.metadata };
}

function wsEventFromGatewayChatPayload(payload: any): WsServerEvent | null {
  if (!payload || typeof payload !== 'object') return null;

  // If gateway already sends our WsServerEvent shape, forward it.
  if (typeof payload.type === 'string' && typeof payload.sessionKey === 'string') {
    return payload as WsServerEvent;
  }

  const sessionKey = typeof payload.sessionKey === 'string' ? payload.sessionKey : '';
  const runId = typeof payload.runId === 'string' ? payload.runId : '';
  if (!sessionKey) return null;

  // Common pattern: { kind: 'delta', delta: { content }, ... }
  if (payload.kind === 'delta' || payload.phase === 'delta') {
    const content = String(payload.delta?.content ?? payload.content ?? '');
    if (!runId || !content) return null;
    return { type: 'message.delta', sessionKey, runId, delta: { content } };
  }

  // Common pattern: { kind: 'message', message: {...} }
  if (payload.kind === 'message' || payload.kind === 'complete' || payload.phase === 'complete' || payload.phase === 'done') {
    const msg = normalizeChatMessage(payload.message ?? payload.msg ?? payload);
    if (!runId || !msg) return null;
    return { type: 'message.complete', sessionKey, runId, message: msg };
  }

  return null;
}

async function main() {
  const cfg = loadConfig();

  // Hard requirement: start only if OpenClaw auth is configured.
  if (!cfg.gateway.token && !cfg.gateway.password) {
    console.error('Missing OpenClaw gateway auth. Set OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD.');
    process.exit(1);
  }

  const store = new SqliteStore(cfg);
  store.init();

  const hub = new RealtimeHub();

  const gateway = new OpenClawGatewayClient({
    url: cfg.gateway.url,
    token: cfg.gateway.token,
    password: cfg.gateway.password,
    minProtocol: cfg.gateway.minProtocol,
    maxProtocol: cfg.gateway.maxProtocol,
    client: {
      // Gateway currently validates client.id against a constant (see webclaw).
      id: 'gateway-client',
      displayName: 'kleoz',
      version: '0.1.0',
      platform: process.platform,
      mode: 'ui',
      instanceId: crypto.randomUUID(),
    },
  });

  gateway.start();
  await gateway.waitForConnected(15_000);

  const { app, onWsMessage } = buildApp({ cfg, store, hub, gateway });

  // Forward gateway chat events to subscribed clients.
  gateway.onEvent((frame) => {
    if (frame.event !== 'chat') return;
    const ev = wsEventFromGatewayChatPayload(frame.payload);
    if (!ev) return;
    if ((ev as any).sessionKey) hub.emitToSession((ev as any).sessionKey, ev);
  });

  const webDistRoot = path.resolve(import.meta.dir, '../../web/dist');

  const server = Bun.serve<{ claims: any }>({
    port: cfg.port,
    hostname: cfg.host,
    fetch: async (req, bunServer) => {
      const url = new URL(req.url);

      if (url.pathname === '/api/ws') {
        const token = url.searchParams.get('token') ?? '';
        if (!token) return new Response('Unauthorized', { status: 401 });
        const claims = await verifyToken(cfg, token).catch(() => null);
        if (!claims) return new Response('Unauthorized', { status: 401 });
        const upgraded = bunServer.upgrade(req, { data: { claims } });
        if (upgraded) return;
        return new Response('Upgrade failed', { status: 400 });
      }

      if (url.pathname.startsWith('/api/')) {
        return app.fetch(req);
      }

      // Static frontend (prod): serve dist/ with SPA fallback.
      // In dev, Vite serves the frontend separately.
      let filePath = url.pathname;
      if (filePath === '/') filePath = '/index.html';
      const abs = path.join(webDistRoot, filePath);
      if (!abs.startsWith(webDistRoot)) return new Response('Not found', { status: 404 });

      const f = Bun.file(abs);
      if (await f.exists()) return new Response(f);

      const index = Bun.file(path.join(webDistRoot, 'index.html'));
      if (await index.exists()) return new Response(index);
      return new Response('Not found', { status: 404 });
    },
    websocket: {
      open: (ws) => {
        hub.register(ws);
      },
      message: (ws, message) => {
        if (typeof message !== 'string') return;
        onWsMessage(ws as any, message);
      },
      close: (ws) => {
        hub.unregister(ws);
      },
    },
  });

  console.log(`kleoz api listening on http://${cfg.host}:${cfg.port}`);
  console.log(`gateway: ${cfg.gateway.url} (connected=${gateway.isConnected()})`);
  void server;
}

void main();
