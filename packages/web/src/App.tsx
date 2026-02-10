import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  ChatMessage,
  MessageAttachment,
  PresenceEntry,
  SessionSummary,
  UserMe,
  WsServerEvent,
} from '@kleoz/contracts';

import { ApiRequestError, getHistory, getMe, getPresence, listSessions, login, logout, sendMessage, uploadMessageFile } from './lib/api';
import { clearAuth, getOrCreateInstanceId, loadAuth, saveAuth } from './lib/storage';
import { WsClient, type WsClientState } from './lib/wsClient';

type ComposerAttachment = {
  id: string;
  file: File;
  dataBase64?: string;
  mimeType: string;
  filename: string;
  kind: 'image' | 'audio' | 'file';
  upload?: { id: string; url: string; expiresAt: string; size: number };
  error?: string;
};

type SessionState = {
  messages: ChatMessage[];
  hasMore: boolean;
  nextCursor?: string;
  loading: boolean;
  streamingByRunId: Record<string, string>;
};

function humanizeError(err: unknown): string {
  if (err instanceof ApiRequestError) {
    const { code, message } = err.apiError;
    if (code === 'UNAUTHORIZED') return 'No autorizado. Vuelve a iniciar sesion.';
    if (code === 'INVALID_REQUEST') return message || 'Solicitud invalida.';
    if (code === 'RATE_LIMIT') return 'Rate limit. Intenta de nuevo en unos segundos.';
    if (code === 'GATEWAY_UNAVAILABLE') return 'Gateway no disponible.';
    return message || `Error (${code})`;
  }
  if (err instanceof Error) return err.message;
  return 'Error desconocido';
}

function byUpdatedAtDesc(a: SessionSummary, b: SessionSummary): number {
  return (b.updatedAt ?? 0) - (a.updatedAt ?? 0);
}

function normalizeSessions(sessions: SessionSummary[]): SessionSummary[] {
  return [...sessions].sort(byUpdatedAtDesc);
}

function mergeSession(sessions: SessionSummary[], next: SessionSummary): SessionSummary[] {
  const idx = sessions.findIndex((s) => s.key === next.key);
  if (idx === -1) return normalizeSessions([...sessions, next]);
  const copy = sessions.slice();
  copy[idx] = { ...copy[idx], ...next };
  return normalizeSessions(copy);
}

function removeSession(sessions: SessionSummary[], sessionKey: string): SessionSummary[] {
  return sessions.filter((s) => s.key !== sessionKey);
}

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('No se pudo leer el archivo.'));
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.readAsDataURL(file);
  });
}

function attachmentTypeFromMime(mimeType: string): 'image' | 'file' | 'audio' {
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType.startsWith('audio/')) return 'audio';
  return 'file';
}

export function App() {
  const [bootError, setBootError] = useState<string>('');
  const [token, setToken] = useState<string>('');
  const [expiresAt, setExpiresAt] = useState<string>('');
  const [user, setUser] = useState<{ id: string; username: string; agentId: string; role: 'admin' | 'user'; createdAt: string } | null>(null);
  const [me, setMe] = useState<UserMe | null>(null);

  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [activeSessionKey, setActiveSessionKey] = useState<string>('');
  const [sessionsState, setSessionsState] = useState<Record<string, SessionState>>({});
  const [includeTools, setIncludeTools] = useState<boolean>(false);

  const [presence, setPresence] = useState<Record<string, PresenceEntry>>({});
  const [presenceMeta, setPresenceMeta] = useState<{ gatewayUptime?: number; timestamp?: number }>({});

  const [wsState, setWsState] = useState<WsClientState>({ status: 'idle' });
  const wsRef = useRef<WsClient | null>(null);

  const [globalNotice, setGlobalNotice] = useState<string>('');
  const [composerText, setComposerText] = useState<string>('');
  const [composerAttachments, setComposerAttachments] = useState<ComposerAttachment[]>([]);
  const [sending, setSending] = useState<boolean>(false);

  const activeSession = useMemo(
    () => sessions.find((s) => s.key === activeSessionKey) ?? null,
    [sessions, activeSessionKey],
  );
  const activeState = useMemo(() => sessionsState[activeSessionKey], [sessionsState, activeSessionKey]);
  const activeMessages = activeState?.messages ?? [];
  const activeStreaming = activeState?.streamingByRunId ?? {};

  // Boot from localStorage.
  useEffect(() => {
    const stored = loadAuth();
    if (!stored) return;
    setToken(stored.token);
    setExpiresAt(stored.expiresAt);
    setUser(stored.user);
  }, []);

  // When token changes, load /me and sessions, connect WS, fetch presence.
  useEffect(() => {
    let cancelled = false;
    async function run() {
      setBootError('');
      setGlobalNotice('');
      if (!token) return;
      try {
        const meOut = await getMe(token);
        if (cancelled) return;
        setMe(meOut);
      } catch (e) {
        if (cancelled) return;
        setBootError(humanizeError(e));
        doLocalLogout(false);
        return;
      }

      try {
        const sessOut = await listSessions(token, 50);
        if (cancelled) return;
        const next = normalizeSessions(sessOut.sessions ?? []);
        setSessions(next);
        if (!activeSessionKey && next.length) setActiveSessionKey(next[0].key);
      } catch (e) {
        if (cancelled) return;
        setGlobalNotice(humanizeError(e));
      }

      try {
        const p = await getPresence(token);
        if (cancelled) return;
        const map: Record<string, PresenceEntry> = {};
        for (const entry of p.entries ?? []) map[entry.instanceId] = entry;
        setPresence(map);
        setPresenceMeta({ gatewayUptime: p.gatewayUptime, timestamp: p.timestamp });
      } catch (e) {
        if (cancelled) return;
        // Presence is best-effort.
      }

      // WS connect after we have a token.
      const instanceId = getOrCreateInstanceId();
      const client = new WsClient({
        token,
        clientInfo: {
          id: 'kleoz-web',
          instanceId,
          version: '0.1.0',
          platform: 'web',
          mode: 'webchat',
          host: window.location.host,
        },
        handlers: {
          onState: (st) => setWsState(st),
          onEvent: (ev) => onWsEvent(ev),
        },
      });
      wsRef.current?.close();
      wsRef.current = client;
      client.connect();
      client.enablePresenceSubscription(true);

      return () => {
        client.close();
      };
    }
    void run();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  // Keep WS subscriptions aligned with "visible" sessions + active session.
  useEffect(() => {
    const keys = new Set<string>(sessions.map((s) => s.key));
    if (activeSessionKey) keys.add(activeSessionKey);
    wsRef.current?.setDesiredSubscriptions(Array.from(keys));
  }, [sessions, activeSessionKey]);

  // Load history when changing sessions.
  useEffect(() => {
    if (!token || !activeSessionKey) return;
    const st = sessionsState[activeSessionKey];
    if (st?.loading) return;
    if (st && st.messages.length) return;
    void loadHistory({ sessionKey: activeSessionKey, reset: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, activeSessionKey]);

  function ensureSessionState(sessionKey: string): SessionState {
    const existing = sessionsState[sessionKey];
    if (existing) return existing;
    const init: SessionState = {
      messages: [],
      hasMore: false,
      nextCursor: undefined,
      loading: false,
      streamingByRunId: {},
    };
    setSessionsState((prev) => ({ ...prev, [sessionKey]: init }));
    return init;
  }

  async function loadHistory(args: { sessionKey: string; reset: boolean }) {
    const sessionKey = args.sessionKey;
    const current = sessionsState[sessionKey] ?? ensureSessionState(sessionKey);
    if (current.loading) return;

    setSessionsState((prev) => ({
      ...prev,
      [sessionKey]: { ...(prev[sessionKey] ?? current), loading: true },
    }));
    try {
      const before = args.reset ? undefined : current.nextCursor;
      const out = await getHistory(token, sessionKey, { limit: 100, includeTools, before });
      const nextMessages = out.messages ?? [];

      setSessionsState((prev) => {
        const prevSt = prev[sessionKey] ?? current;
        const merged = args.reset ? nextMessages : [...nextMessages, ...prevSt.messages];
        // De-dupe by id while preserving order.
        const seen = new Set<string>();
        const deduped: ChatMessage[] = [];
        for (const m of merged) {
          if (seen.has(m.id)) continue;
          seen.add(m.id);
          deduped.push(m);
        }
        return {
          ...prev,
          [sessionKey]: {
            ...prevSt,
            messages: deduped,
            hasMore: Boolean(out.hasMore),
            nextCursor: out.nextCursor,
            loading: false,
          },
        };
      });
    } catch (e) {
      setGlobalNotice(humanizeError(e));
      setSessionsState((prev) => ({
        ...prev,
        [sessionKey]: { ...(prev[sessionKey] ?? current), loading: false },
      }));
    }
  }

  function onWsEvent(event: WsServerEvent) {
    if (!event || typeof event !== 'object' || !('type' in event)) return;

    if (event.type === 'session.created') {
      setSessions((prev) => mergeSession(prev, event.session));
      return;
    }
    if (event.type === 'session.updated') {
      setSessions((prev) => {
        const idx = prev.findIndex((s) => s.key === event.sessionKey);
        if (idx === -1) return prev;
        const copy = prev.slice();
        copy[idx] = { ...copy[idx], ...event.changes };
        return normalizeSessions(copy);
      });
      return;
    }
    if (event.type === 'session.deleted') {
      setSessions((prev) => removeSession(prev, event.sessionKey));
      setSessionsState((prev) => {
        const copy = { ...prev };
        delete copy[event.sessionKey];
        return copy;
      });
      if (activeSessionKey === event.sessionKey) setActiveSessionKey('');
      return;
    }
    if (event.type === 'session.status') {
      setSessions((prev) => {
        const idx = prev.findIndex((s) => s.key === event.sessionKey);
        if (idx === -1) return prev;
        const copy = prev.slice();
        copy[idx] = { ...copy[idx], status: event.status, updatedAt: Math.max(copy[idx].updatedAt ?? 0, Date.now()) };
        return normalizeSessions(copy);
      });
      return;
    }

    if (event.type === 'message.delta') {
      const { sessionKey, runId, delta } = event;
      const content = String(delta?.content ?? '');
      if (!sessionKey || !runId || !content) return;
      setSessionsState((prev) => {
        const st = prev[sessionKey] ?? {
          messages: [],
          hasMore: false,
          nextCursor: undefined,
          loading: false,
          streamingByRunId: {},
        };
        const prevText = st.streamingByRunId[runId] ?? '';
        return {
          ...prev,
          [sessionKey]: {
            ...st,
            streamingByRunId: { ...st.streamingByRunId, [runId]: prevText + content },
          },
        };
      });
      return;
    }

    if (event.type === 'message.complete') {
      const { sessionKey, runId, message } = event;
      if (!sessionKey || !runId || !message?.id) return;
      setSessionsState((prev) => {
        const st = prev[sessionKey] ?? {
          messages: [],
          hasMore: false,
          nextCursor: undefined,
          loading: false,
          streamingByRunId: {},
        };
        const streaming = { ...st.streamingByRunId };
        delete streaming[runId];
        const already = st.messages.some((m) => m.id === message.id);
        const nextMessages = already ? st.messages : [...st.messages, message];
        return {
          ...prev,
          [sessionKey]: { ...st, messages: nextMessages, streamingByRunId: streaming },
        };
      });
      // Touch updatedAt for ordering.
      setSessions((prev) => {
        const idx = prev.findIndex((s) => s.key === sessionKey);
        if (idx === -1) return prev;
        const copy = prev.slice();
        copy[idx] = { ...copy[idx], updatedAt: Math.max(copy[idx].updatedAt ?? 0, Date.now()) };
        return normalizeSessions(copy);
      });
      return;
    }

    if (event.type === 'tool.call' || event.type === 'tool.result') {
      // Minimal handling: surface in notice area for now (keeps protocol covered).
      const name = event.tool?.name ?? 'tool';
      setGlobalNotice(`[${event.type}] ${name} (${event.tool?.status ?? 'unknown'})`);
      return;
    }

    if (event.type === 'presence.snapshot') {
      const map: Record<string, PresenceEntry> = {};
      for (const e of event.entries ?? []) map[e.instanceId] = e;
      setPresence(map);
      return;
    }
    if (event.type === 'presence.updated') {
      setPresence((prev) => {
        const copy = { ...prev };
        for (const e of event.entries ?? []) copy[e.instanceId] = e;
        return copy;
      });
      return;
    }
    if (event.type === 'presence.joined') {
      setPresence((prev) => ({ ...prev, [event.entry.instanceId]: event.entry }));
      return;
    }
    if (event.type === 'presence.left') {
      setPresence((prev) => {
        const copy = { ...prev };
        delete copy[event.instanceId];
        return copy;
      });
      return;
    }

    if (event.type === 'error') {
      const prefix = event.sessionKey ? `(${event.sessionKey}) ` : '';
      setGlobalNotice(`${prefix}${event.error.code}: ${event.error.message}`);
      return;
    }
  }

  async function doLogin(username: string, password: string) {
    setBootError('');
    setGlobalNotice('');
    try {
      const out = await login({ username, password });
      setToken(out.token);
      setExpiresAt(out.expiresAt);
      setUser(out.user);
      saveAuth({ token: out.token, expiresAt: out.expiresAt, user: out.user });
    } catch (e) {
      setBootError(humanizeError(e));
    }
  }

  async function doLocalLogout(callBackend: boolean) {
    const t = token;
    wsRef.current?.close();
    wsRef.current = null;
    setToken('');
    setExpiresAt('');
    setUser(null);
    setMe(null);
    setSessions([]);
    setActiveSessionKey('');
    setSessionsState({});
    setPresence({});
    clearAuth();
    if (callBackend && t) {
      try {
        await logout(t);
      } catch {
        // Ignore.
      }
    }
  }

  async function handlePickFiles(files: FileList | null) {
    if (!files || files.length === 0) return;
    const list = Array.from(files);
    for (const file of list) {
      const id = crypto.randomUUID();
      const kind = attachmentTypeFromMime(file.type || 'application/octet-stream');
      const att: ComposerAttachment = {
        id,
        file,
        mimeType: file.type || 'application/octet-stream',
        filename: file.name || 'file',
        kind,
      };
      setComposerAttachments((prev) => [...prev, att]);

      // Upload (contract: /api/messages/upload).
      void (async () => {
        try {
          const out = await uploadMessageFile(token, file);
          setComposerAttachments((prev) =>
            prev.map((a) => (a.id === id ? { ...a, upload: { id: out.id, url: out.url, expiresAt: out.expiresAt, size: out.size } } : a)),
          );
        } catch (e) {
          setComposerAttachments((prev) =>
            prev.map((a) => (a.id === id ? { ...a, error: humanizeError(e) } : a)),
          );
        }
      })();

      // Base64 (for send attachments per contract).
      void (async () => {
        try {
          const dataUrl = await readFileAsDataUrl(file);
          const comma = dataUrl.indexOf(',');
          const base64 = comma >= 0 ? dataUrl.slice(comma + 1) : dataUrl;
          setComposerAttachments((prev) => prev.map((a) => (a.id === id ? { ...a, dataBase64: base64 } : a)));
        } catch (e) {
          setComposerAttachments((prev) => prev.map((a) => (a.id === id ? { ...a, error: humanizeError(e) } : a)));
        }
      })();
    }
  }

  async function handleSend() {
    if (!token || !activeSessionKey) return;
    if (!me?.permissions?.canSendMessages) {
      setGlobalNotice('No tienes permisos para enviar mensajes.');
      return;
    }
    const text = composerText.trim();
    if (!text && composerAttachments.length === 0) return;

    const attachments: MessageAttachment[] = [];
    for (const a of composerAttachments) {
      if (!a.dataBase64) continue;
      attachments.push({
        type: a.kind,
        data: a.dataBase64,
        filename: a.filename,
        mimeType: a.mimeType,
      });
    }

    setSending(true);
    setGlobalNotice('');
    try {
      await sendMessage(token, {
        sessionKey: activeSessionKey,
        message: text,
        attachments: attachments.length ? attachments : undefined,
      });
      setComposerText('');
      setComposerAttachments([]);
    } catch (e) {
      setGlobalNotice(humanizeError(e));
    } finally {
      setSending(false);
    }
  }

  if (!token || !user) {
    return (
      <main className="app-shell">
        <div className="login-card">
          <div className="brand">
            <div className="brand-title">kleoz</div>
            <div className="brand-subtitle">Web chat</div>
          </div>
          <LoginForm onLogin={doLogin} error={bootError} />
          <div className="muted small">
            Consejo: el backend define usuarios. Si falla, revisa el error exacto arriba.
          </div>
        </div>
      </main>
    );
  }

  const wsBadge =
    wsState.status === 'open'
      ? { cls: 'ok', text: `WS: conectado${wsState.wsSessionId ? ` (${wsState.wsSessionId})` : ''}` }
      : wsState.status === 'connecting'
        ? { cls: 'warn', text: 'WS: conectando...' }
        : wsState.status === 'error'
          ? { cls: 'bad', text: `WS: error${wsState.lastError ? ` (${wsState.lastError.code})` : ''}` }
          : { cls: 'muted', text: 'WS: desconectado' };

  const presenceList = Object.values(presence).sort((a, b) => (a.host || '').localeCompare(b.host || ''));

  return (
    <main className="layout">
      <aside className="sidebar">
        <div className="sidebar-top">
          <div className="user-row">
            <div className="user-meta">
              <div className="user-name">{user.username}</div>
              <div className="muted small">
                {user.role} · exp {new Date(expiresAt).toLocaleString()}
              </div>
            </div>
            <button className="btn" onClick={() => void doLocalLogout(true)}>
              Logout
            </button>
          </div>

          <div className={`badge ${wsBadge.cls}`}>{wsBadge.text}</div>
          {globalNotice ? <div className="notice">{globalNotice}</div> : null}
        </div>

        <div className="sidebar-section">
          <div className="section-title">Sesiones</div>
          <div className="sessions">
            {sessions.length === 0 ? <div className="muted small">Sin sesiones.</div> : null}
            {sessions.map((s) => (
              <button
                key={s.key}
                className={`session-item ${s.key === activeSessionKey ? 'active' : ''}`}
                onClick={() => setActiveSessionKey(s.key)}
                title={s.key}
              >
                <div className="session-main">
                  <div className="session-title">{s.displayName || s.channel || s.key}</div>
                  <div className="muted small">
                    {s.kind} · {new Date(s.updatedAt).toLocaleString()}
                  </div>
                </div>
                <div className={`status-pill ${s.status ?? 'idle'}`}>{s.status ?? 'idle'}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="sidebar-section">
          <div className="section-title">
            Presence <span className="muted small">({presenceList.length})</span>
          </div>
          {presenceMeta.timestamp ? (
            <div className="muted small">ts: {new Date(presenceMeta.timestamp).toLocaleString()}</div>
          ) : null}
          <div className="presence">
            {presenceList.length === 0 ? <div className="muted small">Sin presencia.</div> : null}
            {presenceList.slice(0, 20).map((p) => (
              <div key={p.instanceId} className="presence-row" title={p.instanceId}>
                <div className="presence-host">{p.host}</div>
                <div className="muted small">
                  {p.mode}
                  {typeof p.lastInputSeconds === 'number' ? ` · ${p.lastInputSeconds}s` : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      </aside>

      <section className="chat">
        <header className="chat-header">
          <div className="chat-title">{activeSession ? activeSession.displayName || activeSession.channel || activeSession.key : 'Selecciona una sesion'}</div>
          <div className="chat-actions">
            <label className="toggle">
              <input
                type="checkbox"
                checked={includeTools}
                onChange={(e) => {
                  setIncludeTools(e.target.checked);
                  if (activeSessionKey) void loadHistory({ sessionKey: activeSessionKey, reset: true });
                }}
              />
              <span>incluir tools</span>
            </label>
            {activeSession?.status ? <div className={`status-pill ${activeSession.status}`}>{activeSession.status}</div> : null}
          </div>
        </header>

        <div className="chat-body">
          {!activeSessionKey ? <div className="muted">Selecciona una sesion en la barra lateral.</div> : null}
          {activeSessionKey ? (
            <>
              <div className="chat-toolbar">
                <button
                  className="btn"
                  disabled={!activeState?.hasMore || activeState?.loading}
                  onClick={() => void loadHistory({ sessionKey: activeSessionKey, reset: false })}
                >
                  {activeState?.loading ? 'Cargando...' : activeState?.hasMore ? 'Cargar mas (older)' : 'Sin mas'}
                </button>
              </div>

              <div className="messages">
                {activeMessages.map((m) => (
                  <MessageBubble key={m.id} msg={m} />
                ))}
                {Object.entries(activeStreaming).map(([runId, text]) => (
                  <div key={runId} className="bubble assistant streaming">
                    <div className="bubble-meta">assistant · streaming</div>
                    <div className="bubble-content">{text}</div>
                  </div>
                ))}
              </div>
            </>
          ) : null}
        </div>

        <footer className="composer">
          <div className="composer-row">
            <textarea
              className="composer-input"
              placeholder={me?.permissions?.canSendMessages ? 'Escribe un mensaje...' : 'No tienes permisos para enviar mensajes.'}
              value={composerText}
              disabled={!me?.permissions?.canSendMessages || sending || !activeSessionKey}
              onChange={(e) => setComposerText(e.target.value)}
            />
          </div>

          <div className="composer-row">
            <input
              className="file-input"
              type="file"
              multiple
              disabled={sending || !activeSessionKey}
              onChange={(e) => void handlePickFiles(e.target.files)}
            />
            <button className="btn primary" disabled={sending || (!composerText.trim() && composerAttachments.length === 0) || !activeSessionKey} onClick={() => void handleSend()}>
              {sending ? 'Enviando...' : 'Enviar'}
            </button>
          </div>

          {composerAttachments.length ? (
            <div className="attachments">
              {composerAttachments.map((a) => (
                <div key={a.id} className="attachment">
                  <div className="attachment-main">
                    <div className="attachment-name">{a.filename}</div>
                    <div className="muted small">
                      {a.mimeType}
                      {a.upload?.url ? (
                        <>
                          {' '}
                          · <a href={a.upload.url} target="_blank" rel="noreferrer">descargar</a>
                        </>
                      ) : null}
                    </div>
                    {a.error ? <div className="error small">{a.error}</div> : null}
                  </div>
                  <button className="btn" onClick={() => setComposerAttachments((prev) => prev.filter((x) => x.id !== a.id))}>
                    Quitar
                  </button>
                </div>
              ))}
            </div>
          ) : null}
        </footer>
      </section>
    </main>
  );
}

function LoginForm(props: { onLogin: (u: string, p: string) => void; error?: string }) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  return (
    <form
      className="login-form"
      onSubmit={(e) => {
        e.preventDefault();
        props.onLogin(username.trim(), password);
      }}
    >
      <label className="field">
        <div className="field-label">Username</div>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" autoComplete="username" />
      </label>
      <label className="field">
        <div className="field-label">Password</div>
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" autoComplete="current-password" />
      </label>
      {props.error ? <div className="error">{props.error}</div> : null}
      <button className="btn primary" type="submit">
        Entrar
      </button>
    </form>
  );
}

function MessageBubble(props: { msg: ChatMessage }) {
  const m = props.msg;
  const cls = m.role === 'user' ? 'user' : m.role === 'assistant' ? 'assistant' : 'tool';
  return (
    <div className={`bubble ${cls}`}>
      <div className="bubble-meta">
        {m.role} · {new Date(m.timestamp).toLocaleString()}
        {m.model ? ` · ${m.model}` : ''}
      </div>
      <div className="bubble-content">{m.content}</div>
    </div>
  );
}

