import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApp } from './server.js';
import { verifyToken } from './auth.js';
import { OpenClawGatewayClient } from './openclaw/gatewayClient.js';
import type { JwtClaims } from './types.js';

const gateway = new OpenClawGatewayClient();
if (!gateway.enabled()) {
  console.error('[kleoz] Missing OpenClaw gateway auth. Set OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD.');
  process.exit(1);
}
gateway.start();
await gateway.waitForConnected(15_000).catch((err) => {
  console.error(`[kleoz] Failed to connect to OpenClaw gateway: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
const { app, hub } = buildApp(undefined, undefined, gateway);

const port = Number(process.env.PORT ?? 3000);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(__dirname, '../../web/dist');

function resolveWebPath(urlPath: string): string {
  // Very small path traversal guard.
  const rel = urlPath.replace(/^\/+/, '');
  const abs = path.resolve(webDist, rel);
  if (!abs.startsWith(webDist)) return path.resolve(webDist, 'index.html');
  return abs;
}

type WsData = { claims: JwtClaims };

Bun.serve<WsData>({
  port,
  async fetch(req, server) {
    const url = new URL(req.url);

    if (url.pathname === '/api/ws') {
      const token = url.searchParams.get('token');
      if (!token) return new Response('Unauthorized', { status: 401 });
      const claims = await verifyToken(token).catch(() => null);
      if (!claims) return new Response('Unauthorized', { status: 401 });

      const ok = server.upgrade(req, { data: { claims } });
      return ok ? new Response(null, { status: 101 }) : new Response('Upgrade failed', { status: 500 });
    }

    if (!url.pathname.startsWith('/api')) {
      // Serve built frontend assets, fallback to index.html for SPA routes.
      const pathname = url.pathname === '/' ? '/index.html' : url.pathname;
      const abs = resolveWebPath(pathname);
      const file = Bun.file(abs);
      if (await file.exists()) return new Response(file);
      return new Response(Bun.file(path.resolve(webDist, 'index.html')));
    }

    return app.fetch(req);
  },
  websocket: {
    open(ws) {
      const claims = ws.data.claims;
      hub.register(ws as any, { userId: claims.sub, username: claims.username, agentId: claims.agentId });
      ws.send(JSON.stringify({ type: 'connected', wsSessionId: crypto.randomUUID() }));
    },
    message(ws, message) {
      try {
        hub.noteInput(ws as any);
        const raw = typeof message === 'string' ? message : Buffer.from(message as any).toString('utf8');
        const data = JSON.parse(raw) as {
          type?: string;
          sessionKeys?: string[];
          token?: string;
          client?: { instanceId?: string; version?: string; platform?: string; mode?: string };
        };
        if (data.type === 'connect' && data.client) hub.updateClient(ws as any, data.client);
        if (data.type === 'subscribe' || data.type === 'sessions.subscribe') hub.setSubscriptions(ws as any, data.sessionKeys ?? []);
        if (data.type === 'unsubscribe') hub.removeSubscriptions(ws as any, data.sessionKeys ?? []);
        if (data.type === 'subscribe.presence') hub.enablePresence(ws as any);
      } catch {
        ws.send(JSON.stringify({ type: 'error', error: { code: 'INVALID_REQUEST', message: 'Malformed message' } }));
      }
    },
    close(ws) {
      hub.unregister(ws as any);
    },
  },
});

console.log(`🦁 kleoz running on http://localhost:${port}`);
