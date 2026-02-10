import { describe, expect, it } from 'vitest';
import { buildApp } from '../src/server.js';

async function login(appFetch: (req: Request) => Promise<Response>, username = 'admin', password = 'admin1234') {
  const res = await appFetch(new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }));
  const json = await res.json();
  return json.token as string;
}

describe('kleoz api', () => {
  it('responds from health endpoint', async () => {
    const { app } = buildApp();
    const res = await app.request('/api/health');
    expect(res.status).toBe(200);
  });

  it('creates session and emits agent message only when @agent is present', async () => {
    const { app } = buildApp();
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
    expect(data.messages.at(-1).sender).toBe('agent');
  });
});
