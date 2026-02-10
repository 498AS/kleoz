import { StrictMode, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type User = { id: string; username: string; role: 'admin' | 'user'; agentId: string };
type Session = { key: string; title: string };
type Message = { id: string; sender: string; body: string; createdAt: string };

function App() {
  const [token, setToken] = useState<string>('');
  const [user, setUser] = useState<User | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeKey, setActiveKey] = useState<string>('');
  const [messagesBySession, setMessagesBySession] = useState<Record<string, Message[]>>({});
  const wsRef = useRef<WebSocket | null>(null);

  const activeMessages = useMemo(() => messagesBySession[activeKey] ?? [], [messagesBySession, activeKey]);

  useEffect(() => {
    if (!token) return;
    fetch('/api/sessions', { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => {
        setSessions(d.sessions ?? []);
        if (d.sessions?.length && !activeKey) setActiveKey(d.sessions[0].key);
      });
  }, [token, activeKey]);

  useEffect(() => {
    if (!token) return;
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/api/ws?token=${encodeURIComponent(token)}`);
    wsRef.current = ws;
    ws.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === 'message.complete') {
        setMessagesBySession((prev) => ({
          ...prev,
          [payload.sessionKey]: [...(prev[payload.sessionKey] ?? []), payload.message],
        }));
      }
    };
    return () => ws.close();
  }, [token]);

  useEffect(() => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      const timer = setInterval(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ type: 'sessions.subscribe', sessionKeys: sessions.map((s) => s.key) }));
          clearInterval(timer);
        }
      }, 100);
      return () => clearInterval(timer);
    }
    wsRef.current.send(JSON.stringify({ type: 'sessions.subscribe', sessionKeys: sessions.map((s) => s.key) }));
  }, [sessions]);

  async function login(formData: FormData) {
    const username = formData.get('username');
    const password = formData.get('password');
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) return;
    const out = await res.json();
    setToken(out.token);
    setUser(out.user);
  }

  async function sendMessage(formData: FormData) {
    const message = String(formData.get('message') ?? '');
    if (!message || !activeKey) return;
    await fetch('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionKey: activeKey, message }),
    });
  }

  async function createSession(formData: FormData) {
    const name = String(formData.get('name') ?? '').trim();
    if (!name) return;
    const key = `agent:${user?.agentId ?? 'main'}:shared:${name}`;
    await fetch('/api/messages/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionKey: key, message: 'Sesión creada', participants: [user?.id] }),
    });
    setSessions((prev) => (prev.find((p) => p.key === key) ? prev : [...prev, { key, title: name }]));
    setActiveKey(key);
  }

  if (!token) {
    return (
      <main className="container">
        <h1>kleoz</h1>
        <p>Login demo (admin/admin1234)</p>
        <form action={login} className="panel">
          <input name="username" placeholder="username" defaultValue="admin" />
          <input name="password" type="password" placeholder="password" defaultValue="admin1234" />
          <button>Entrar</button>
        </form>
      </main>
    );
  }

  return (
    <main className="layout">
      <aside>
        <h2>{user?.username}</h2>
        <form action={createSession} className="inline">
          <input name="name" placeholder="nueva sesión" />
          <button>+</button>
        </form>
        {sessions.map((s) => (
          <button key={s.key} onClick={() => setActiveKey(s.key)} className={s.key === activeKey ? 'active' : ''}>
            {s.title}
          </button>
        ))}
      </aside>
      <section>
        <header>{activeKey || 'Selecciona sesión'}</header>
        <div className="messages">
          {activeMessages.map((m) => (
            <article key={m.id}>
              <b>{m.sender}</b>: {m.body}
            </article>
          ))}
        </div>
        <form action={sendMessage} className="inline">
          <input name="message" placeholder="Escribe... usa @agent para respuesta" />
          <button>Enviar</button>
        </form>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
