import { serve } from '@hono/node-server';
import { WebSocketServer } from 'ws';
import { buildApp, attachWsHandlers } from './server.js';
import { verifyToken } from './auth.js';

const { app, hub } = buildApp();
const server = serve({ fetch: app.fetch, port: Number(process.env.PORT ?? 3000) });
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
