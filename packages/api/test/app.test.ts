import { describe, expect, it } from 'bun:test';

import { buildApp, type GatewayLike } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { SqliteStore } from '../src/store.js';
import { RealtimeHub } from '../src/realtime.js';

async function login(appFetch: (req: Request) => Promise<Response>, username = 'admin', password = 'admin1234') {
  const res = await appFetch(new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }));
  const json = await res.json();
  return json.token as string;
}

function makeTestGateway(): GatewayLike {
  return {
    isConnected: () => true,
    getLatencyMs: () => 1,
    rpc: async (method: string, params?: unknown) => {
      if (method === 'sessions.list') return { sessions: [] } as any;
      if (method === 'sessions.delete') return { ok: true } as any;
      if (method === 'chat.send') return { runId: 'run_test_1' } as any;
      if (method === 'chat.history') {
        return {
          messages: [
            { id: 'm1', role: 'assistant', content: 'ok', timestamp: new Date().toISOString() },
          ],
          hasMore: false,
        } as any;
      }
      return {} as any;
    },
  };
}

describe('kleoz api', () => {
  it('responds from health endpoint', async () => {
    const cfg = loadConfig();
    cfg.databasePath = ':memory:';
    const store = new SqliteStore(cfg);
    store.init();
    const { app } = buildApp({ cfg, store, hub: new RealtimeHub(), gateway: makeTestGateway() });
    const res = await app.request('/api/health');
    expect(res.status).toBe(200);
  });

  it('login works with default admin', async () => {
    const cfg = loadConfig();
    cfg.databasePath = ':memory:';
    cfg.adminPassword = 'admin1234';
    const store = new SqliteStore(cfg);
    store.init();
    const { app } = buildApp({ cfg, store, hub: new RealtimeHub(), gateway: makeTestGateway() });
    const token = await login(app.request.bind(app));
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(10);
  });

  it('send message persists local message and allows history retrieval', async () => {
    const cfg = loadConfig();
    cfg.databasePath = ':memory:';
    cfg.adminPassword = 'admin1234';
    const store = new SqliteStore(cfg);
    store.init();
    const { app } = buildApp({ cfg, store, hub: new RealtimeHub(), gateway: makeTestGateway() });
    const token = await login(app.request.bind(app));

    await app.request('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionKey: 'agent:main:dm:test', message: 'hola' }),
    });

    const history = await app.request('/api/sessions/agent%3Amain%3Adm%3Atest/history', {
      headers: { authorization: `Bearer ${token}` },
    });
    const data = await history.json();
    expect(Array.isArray(data.messages)).toBe(true);
    expect(data.messages.length).toBeGreaterThan(0);
  });
});
