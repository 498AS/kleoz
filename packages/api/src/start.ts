import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { WebSocketServer } from 'ws';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApp, attachWsHandlers } from './server.js';
import { verifyToken } from './auth.js';
import { OpenClawGatewayClient } from './openclaw/gatewayClient.js';

const gateway = new OpenClawGatewayClient();
gateway.start();
const { app, hub } = buildApp(undefined, undefined, gateway);

// Serve static files from web dist
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(__dirname, '../../web/dist');
app.use('/*', async (c, next) => {
  if (c.req.path.startsWith('/api')) return next();
  return serveStatic({ root: webDist })(c, next);
});

const port = Number(process.env.PORT ?? 3000);
const server = serve({ fetch: app.fetch, port });
const wss = new WebSocketServer({ noServer: true });
attachWsHandlers(wss, hub);

server.on('upgrade', (request, socket, head) => {
  if (!request.url?.startsWith('/api/ws')) return socket.destroy();
  const token = new URL(request.url, 'http://localhost').searchParams.get('token');
  if (!token) return socket.destroy();
  verifyToken(token)
    .then((claims) => wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, claims)))
    .catch(() => socket.destroy());
});

console.log(`🦁 kleoz running on http://localhost:${port}`);
