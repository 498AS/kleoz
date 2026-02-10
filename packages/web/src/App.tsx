import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  ChatMessage,
  MessageAttachment,
  PresenceEntry,
  SessionDetail,
  SessionSummary,
  UserMe,
  WsServerEvent,
} from '@kleoz/contracts';

import {
  ApiRequestError,
  deleteSession,
  getHistory,
  getMe,
  getPresence,
  getSession,
  listSessions,
  login,
  logout,
  sendMessage,
  uploadMessageFile,
} from '@/lib/api';
import { clearAuth, getOrCreateInstanceId, loadAuth, saveAuth } from '@/lib/storage';
import { WsClient, type WsClientState } from '@/lib/wsClient';
import { cn } from '@/lib/utils';

import { AppSidebar } from '@/components/app-sidebar';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar';
import { Textarea } from '@/components/ui/textarea';
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

import { CheckCircle2, Loader2, LogOut, Paperclip, Send, Trash2, Wifi, WifiOff } from 'lucide-react';

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
  const [user, setUser] = useState<{
    id: string;
    username: string;
    agentId: string;
    role: 'admin' | 'user';
    createdAt: string;
  } | null>(null);
  const [me, setMe] = useState<UserMe | null>(null);

  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [activeSessionKey, setActiveSessionKey] = useState<string>('');
  const [activeSessionDetail, setActiveSessionDetail] = useState<SessionDetail | null>(null);
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

  const [deleteDialogOpen, setDeleteDialogOpen] = useState<boolean>(false);
  const [deleteTargetKey, setDeleteTargetKey] = useState<string>('');

  const activeSession = useMemo(
    () => sessions.find((s) => s.key === activeSessionKey) ?? null,
    [sessions, activeSessionKey],
  );
  const activeState = useMemo(() => sessionsState[activeSessionKey], [sessionsState, activeSessionKey]);
  const activeMessages = activeState?.messages ?? [];
  const activeStreaming = activeState?.streamingByRunId ?? {};
  const attachmentsPending = useMemo(
    () => composerAttachments.some((a) => !a.dataBase64 && !a.error),
    [composerAttachments],
  );

  const wsBadge = useMemo(() => {
    if (wsState.status === 'open') return { variant: 'secondary' as const, icon: Wifi, text: 'WS conectado' };
    if (wsState.status === 'connecting') return { variant: 'outline' as const, icon: Loader2, text: 'WS conectando' };
    if (wsState.status === 'error') return { variant: 'destructive' as const, icon: WifiOff, text: 'WS error' };
    return { variant: 'outline' as const, icon: WifiOff, text: 'WS offline' };
  }, [wsState.status]);

  const presenceList = useMemo(
    () => Object.values(presence).sort((a, b) => (a.host || '').localeCompare(b.host || '')),
    [presence],
  );

  useEffect(() => {
    const stored = loadAuth();
    if (!stored) return;
    setToken(stored.token);
    setExpiresAt(stored.expiresAt);
    setUser(stored.user);
  }, []);

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
      } catch {
        // Presence is best-effort.
      }

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

  useEffect(() => {
    const keys = new Set<string>(sessions.map((s) => s.key));
    if (activeSessionKey) keys.add(activeSessionKey);
    wsRef.current?.setDesiredSubscriptions(Array.from(keys));
  }, [sessions, activeSessionKey]);

  useEffect(() => {
    if (!token || !activeSessionKey) {
      setActiveSessionDetail(null);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const d = await getSession(token, activeSessionKey);
        if (cancelled) return;
        setActiveSessionDetail(d);
      } catch {
        if (cancelled) return;
        setActiveSessionDetail(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token, activeSessionKey]);

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
    setActiveSessionDetail(null);
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

      void (async () => {
        try {
          const out = await uploadMessageFile(token, file);
          setComposerAttachments((prev) =>
            prev.map((a) =>
              a.id === id
                ? { ...a, upload: { id: out.id, url: out.url, expiresAt: out.expiresAt, size: out.size } }
                : a,
            ),
          );
        } catch (e) {
          setComposerAttachments((prev) => prev.map((a) => (a.id === id ? { ...a, error: humanizeError(e) } : a)));
        }
      })();

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

    if (attachmentsPending) {
      setGlobalNotice('Esperando a procesar attachments (base64).');
      return;
    }

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

  async function handleConfirmDeleteSession() {
    const key = deleteTargetKey;
    if (!token || !key) return;
    setDeleteDialogOpen(false);
    setDeleteTargetKey('');
    setGlobalNotice('');

    try {
      await deleteSession(token, key);
      setSessions((prev) => removeSession(prev, key));
      setSessionsState((prev) => {
        const copy = { ...prev };
        delete copy[key];
        return copy;
      });
      if (activeSessionKey === key) setActiveSessionKey('');
    } catch (e) {
      setGlobalNotice(humanizeError(e));
    }
  }

  if (!token || !user) {
    return (
      <div className="min-h-svh p-6 md:p-10">
        <div className="mx-auto flex w-full max-w-sm flex-col justify-center gap-6">
          <Card>
            <CardHeader>
              <CardTitle>kleoz</CardTitle>
              <CardDescription>Login para acceder al chat</CardDescription>
            </CardHeader>
            <CardContent>
              <LoginForm onLogin={doLogin} error={bootError} />
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const sessionTitle = activeSession?.displayName || activeSession?.channel || activeSession?.key || 'Selecciona una sesion';

  return (
    <SidebarProvider>
      <AppSidebar
        user={user}
        sessions={sessions}
        activeSessionKey={activeSessionKey}
        onCreateSession={() => {
          const agentId = me?.agentId || user.agentId || 'main';
          const peer = `web-${crypto.randomUUID().slice(0, 8)}`;
          const key = `agent:${agentId}:dm:${peer}`;
          const now = Date.now();
          const summary: SessionSummary = {
            key,
            sessionId: `local:${crypto.randomUUID()}`,
            kind: 'dm',
            channel: 'webchat',
            displayName: peer,
            updatedAt: now,
            status: 'idle',
          };
          setSessions((prev) => mergeSession(prev, summary));
          setActiveSessionKey(key);
        }}
        onSelectSession={(k) => setActiveSessionKey(k)}
        wsState={wsState}
        presenceList={presenceList}
        presenceMeta={presenceMeta}
        onRequestDelete={(k) => {
          setDeleteTargetKey(k);
          setDeleteDialogOpen(true);
        }}
      />

      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b">
          <div className="flex items-center gap-2 px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />

            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem className="hidden md:block">
                  <BreadcrumbLink href="#" onClick={(e) => e.preventDefault()}>
                    Sesiones
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage className="max-w-[44vw] truncate">{sessionTitle}</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>

          <div className="ml-auto flex items-center gap-2 px-4">
            <Badge variant={wsBadge.variant} className="hidden md:inline-flex">
              <wsBadge.icon
                className={cn('mr-1 h-3.5 w-3.5', wsState.status === 'connecting' ? 'animate-spin' : '')}
              />
              {wsBadge.text}
            </Badge>

            {activeSession?.status ? (
              <Badge
                variant={
                  activeSession.status === 'idle'
                    ? 'secondary'
                    : activeSession.status === 'thinking'
                      ? 'outline'
                      : 'default'
                }
              >
                {activeSession.status}
              </Badge>
            ) : null}

            <div className="hidden items-center gap-2 md:flex">
              <Switch
                id="include-tools"
                checked={includeTools}
                onCheckedChange={(v) => {
                  setIncludeTools(Boolean(v));
                  if (activeSessionKey) void loadHistory({ sessionKey: activeSessionKey, reset: true });
                }}
              />
              <Label htmlFor="include-tools" className="text-xs text-muted-foreground">
                tools
              </Label>
            </div>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="gap-2">
                  <span className="hidden sm:inline">{user.username}</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>Cuenta</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem disabled>
                  <span className="text-xs text-muted-foreground">
                    {user.role} · exp {new Date(expiresAt).toLocaleString()}
                  </span>
                </DropdownMenuItem>
                {activeSessionDetail?.transcriptPath ? (
                  <DropdownMenuItem disabled>
                    <span className="text-xs text-muted-foreground">transcript: {activeSessionDetail.transcriptPath}</span>
                  </DropdownMenuItem>
                ) : null}
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => void doLocalLogout(true)} className="gap-2">
                  <LogOut className="h-4 w-4" />
                  Logout
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        {globalNotice ? (
          <div className="p-4">
            <Alert>
              <AlertTitle>Info</AlertTitle>
              <AlertDescription>{globalNotice}</AlertDescription>
            </Alert>
          </div>
        ) : null}

        <div className="flex min-h-0 flex-1 flex-col">
          <div className="flex items-center gap-2 border-b px-4 py-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!activeState?.hasMore || activeState?.loading || !activeSessionKey}
              onClick={() => activeSessionKey && void loadHistory({ sessionKey: activeSessionKey, reset: false })}
            >
              {activeState?.loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Cargando...
                </>
              ) : activeState?.hasMore ? (
                'Cargar mas (older)'
              ) : (
                'Sin mas'
              )}
            </Button>

            <div className="ml-auto flex items-center gap-2 md:hidden">
              <Switch
                id="include-tools-mobile"
                checked={includeTools}
                onCheckedChange={(v) => {
                  setIncludeTools(Boolean(v));
                  if (activeSessionKey) void loadHistory({ sessionKey: activeSessionKey, reset: true });
                }}
              />
              <Label htmlFor="include-tools-mobile" className="text-xs text-muted-foreground">
                tools
              </Label>
            </div>
          </div>

          <ScrollArea className="min-h-0 flex-1">
            <div className="mx-auto w-full max-w-4xl space-y-3 p-4">
              {!activeSessionKey ? <div className="text-sm text-muted-foreground">Selecciona una sesion en el sidebar.</div> : null}

              {activeMessages.map((m) => (
                <MessageBubble key={m.id} msg={m} />
              ))}

              {Object.entries(activeStreaming).map(([runId, text]) => (
                <div key={runId} className="rounded-lg border bg-muted/30 p-3">
                  <div className="mb-2 text-xs text-muted-foreground">assistant · streaming</div>
                  <div className="whitespace-pre-wrap text-sm leading-relaxed">{text}</div>
                </div>
              ))}
            </div>
          </ScrollArea>

          <div className="border-t p-4">
            <div className="mx-auto w-full max-w-4xl space-y-3">
              {composerAttachments.length ? (
                <div className="space-y-2">
                  {composerAttachments.map((a) => (
                    <div key={a.id} className="flex items-center justify-between gap-3 rounded-lg border bg-card/30 p-2">
                      <div className="min-w-0">
                        <div className="truncate text-sm">{a.filename}</div>
                        <div className="text-xs text-muted-foreground">
                          {a.mimeType}
                          {!a.dataBase64 && !a.error ? ' · procesando...' : ''}
                          {a.upload?.url ? (
                            <>
                              {' '}
                              ·{' '}
                              <a className="underline" href={a.upload.url} target="_blank" rel="noreferrer">
                                descargar
                              </a>
                            </>
                          ) : null}
                        </div>
                        {a.error ? <div className="text-xs text-destructive">{a.error}</div> : null}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setComposerAttachments((prev) => prev.filter((x) => x.id !== a.id))}
                      >
                        Quitar
                      </Button>
                    </div>
                  ))}
                </div>
              ) : null}

              <Textarea
                placeholder={me?.permissions?.canSendMessages ? 'Escribe un mensaje...' : 'No tienes permisos para enviar mensajes.'}
                value={composerText}
                disabled={!me?.permissions?.canSendMessages || sending || !activeSessionKey}
                onChange={(e) => setComposerText(e.target.value)}
              />

              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <div className="flex items-center gap-2">
                  <Label className="inline-flex items-center gap-2 text-xs text-muted-foreground">
                    <Paperclip className="h-4 w-4" />
                    Adjuntos
                  </Label>
                  <Input
                    type="file"
                    multiple
                    className="w-full sm:w-[260px]"
                    disabled={sending || !activeSessionKey}
                    onChange={(e) => void handlePickFiles(e.target.files)}
                  />
                </div>

                <div className="sm:ml-auto">
                  <Button
                    className="w-full sm:w-auto"
                    disabled={
                      sending || attachmentsPending || (!composerText.trim() && composerAttachments.length === 0) || !activeSessionKey
                    }
                    onClick={() => void handleSend()}
                  >
                    {sending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Send className="mr-2 h-4 w-4" />}
                    Enviar
                  </Button>
                </div>
              </div>

              <div className="text-xs text-muted-foreground">
                Fuente de verdad: WS `message.complete`. Uploads solo dan `url` para preview/descarga.
              </div>
            </div>
          </div>
        </div>
      </SidebarInset>

      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Eliminar sesion</AlertDialogTitle>
            <AlertDialogDescription>
              Esto borrara la sesion y su historial. sessionKey: <span className="font-mono">{deleteTargetKey}</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction onClick={() => void handleConfirmDeleteSession()} className="gap-2">
              <Trash2 className="h-4 w-4" />
              Eliminar
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </SidebarProvider>
  );
}

function LoginForm(props: { onLogin: (u: string, p: string) => void; error?: string }) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        props.onLogin(username.trim(), password);
      }}
    >
      <div className="space-y-2">
        <Label htmlFor="username">Username</Label>
        <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          type="password"
          autoComplete="current-password"
        />
      </div>

      {props.error ? (
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{props.error}</AlertDescription>
        </Alert>
      ) : null}

      <Button type="submit" className="w-full">
        Entrar
      </Button>
    </form>
  );
}

function MessageBubble(props: { msg: ChatMessage }) {
  const m = props.msg;
  const isUser = m.role === 'user';
  const isTool = m.role === 'tool';

  return (
    <div
      className={cn(
        'rounded-lg border p-3',
        isUser ? 'ml-auto bg-primary/10' : 'bg-card/30',
        isTool ? 'border-dashed' : '',
      )}
    >
      <div className="mb-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <span className="font-mono">{m.role}</span>
        <span>·</span>
        <span>{new Date(m.timestamp).toLocaleString()}</span>
        {m.model ? (
          <>
            <span>·</span>
            <span className="font-mono">{m.model}</span>
          </>
        ) : null}
        {m.tokens?.input != null || m.tokens?.output != null ? (
          <>
            <span>·</span>
            <span className="font-mono">
              in {m.tokens?.input ?? '-'} / out {m.tokens?.output ?? '-'}
            </span>
          </>
        ) : null}
        {!isTool && m.role === 'assistant' ? <CheckCircle2 className="ml-auto h-3.5 w-3.5" /> : null}
      </div>
      <div className="whitespace-pre-wrap text-sm leading-relaxed">{m.content}</div>
    </div>
  );
}

function initials(username: string): string {
  const clean = (username || '').trim();
  if (!clean) return 'U';
  const parts = clean.split(/\s+/g).filter(Boolean);
  const first = parts[0]?.[0] ?? 'U';
  const second = parts[1]?.[0] ?? parts[0]?.[1] ?? '';
  return (first + second).toUpperCase();
}
