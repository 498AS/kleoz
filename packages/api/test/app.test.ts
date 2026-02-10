import { describe, expect, it } from 'bun:test';
import { buildApp } from '../src/server.js';
import { SQLiteStore } from '../src/store.js';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';

async function login(appFetch: (req: Request) => Promise<Response>, username = 'admin', password = 'admin1234') {
  const res = await appFetch(new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }));
  const json = await res.json();
  return json.token as string;
}

async function createUser(appFetch: (path: string, init?: RequestInit) => Promise<Response>, token: string, input: { username: string; password: string; role?: 'admin' | 'user'; agentId?: string }) {
  const res = await appFetch('/api/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ username: input.username, password: input.password, role: input.role ?? 'user', agentId: input.agentId ?? 'main' }),
  });
  return res;
}

describe('kleoz api', () => {
  it('responds from health endpoint', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'kleoz-test-'));
    const store = new SQLiteStore({ dataDir: tmp, dbPath: path.join(tmp, 'kleoz.db'), uploadsDir: path.join(tmp, 'uploads') });
    const { app } = buildApp(store);
    const res = await app.request('/api/health');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
  });

  it('creates session and emits agent message only when @agent is present', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'kleoz-test-'));
    const store = new SQLiteStore({ dataDir: tmp, dbPath: path.join(tmp, 'kleoz.db'), uploadsDir: path.join(tmp, 'uploads') });
    const { app } = buildApp(store);
    const token = await login(app.request.bind(app));

    await app.request('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionKey: 'agent:main:shared:sync', message: 'hola equipo' }),
    });

    let history = await app.request('/api/sessions/agent%3Amain%3Ashared%3Async/history', {
      headers: { authorization: `Bearer ${token}` },
    });
    let data = await history.json();
    expect(data.messages).toHaveLength(1);
    expect(data.messages[0].role).toBe('user');

    await app.request('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionKey: 'agent:main:shared:sync', message: '@agent dame estado' }),
    });

    history = await app.request('/api/sessions/agent%3Amain%3Ashared%3Async/history', {
      headers: { authorization: `Bearer ${token}` },
    });
    data = await history.json();
    expect(data.messages).toHaveLength(3);
    expect(data.messages.at(-1).role).toBe('assistant');
  });

  it('DM sessions auto-trigger the agent and are not joinable by other users', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'kleoz-test-'));
    const store = new SQLiteStore({ dataDir: tmp, dbPath: path.join(tmp, 'kleoz.db'), uploadsDir: path.join(tmp, 'uploads') });
    const { app } = buildApp(store);

    const adminToken = await login(app.request.bind(app));
    await createUser(app.request.bind(app), adminToken, { username: 'u1', password: 'password123', agentId: 'main' });
    await createUser(app.request.bind(app), adminToken, { username: 'u2', password: 'password123', agentId: 'main' });

    const u1Token = await login(app.request.bind(app), 'u1', 'password123');
    const u2Token = await login(app.request.bind(app), 'u2', 'password123');

    await app.request('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${u1Token}` },
      body: JSON.stringify({ sessionKey: 'agent:main:dm:private', message: 'hola' }),
    });

    const h1 = await app.request('/api/sessions/agent%3Amain%3Adm%3Aprivate/history', {
      headers: { authorization: `Bearer ${u1Token}` },
    });
    const d1 = await h1.json();
    expect(d1.messages).toHaveLength(2);
    expect(d1.messages[0].role).toBe('user');
    expect(d1.messages[1].role).toBe('assistant');

    // u2 cannot post into u1's DM by guessing the key.
    const res = await app.request('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${u2Token}` },
      body: JSON.stringify({ sessionKey: 'agent:main:dm:private', message: 'yo tambien' }),
    });
    expect(res.status).toBe(403);
  });
});
