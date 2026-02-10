// Canonical API/WS contracts shared between @kleoz/api and @kleoz/web.
// Keep this file free of runtime deps so both packages can import types cheaply.

export type Role = 'admin' | 'user';

export type ApiErrorCode =
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'INVALID_REQUEST'
  | 'RATE_LIMIT'
  | 'GATEWAY_UNAVAILABLE'
  | 'AGENT_TIMEOUT';

export type ApiError = {
  code: ApiErrorCode;
  message: string;
  details?: Record<string, unknown>;
};

export type ApiErrorResponse = {
  error: ApiError;
};

export type UserPublic = {
  id: string;
  username: string;
  agentId: string;
  role: Role;
  createdAt: string; // ISO8601
};

export type UserMe = {
  id: string;
  username: string;
  agentId: string;
  role: Role;
  permissions: {
    canSendMessages: boolean;
    canViewAllSessions: boolean;
    canManageUsers: boolean;
  };
};

export type AuthLoginRequest = {
  username: string;
  password: string;
};

export type AuthLoginResponse = {
  token: string;
  expiresAt: string; // ISO8601
  user: UserPublic;
};

export type AuthLogoutResponse = { ok: true };

export type SessionKind = 'dm' | 'group' | 'channel';

export type SessionOrigin = {
  label?: string;
  provider?: string;
  from?: string;
};

export type SessionSummary = {
  key: string;
  sessionId: string;
  kind: SessionKind;
  channel: string;
  displayName?: string;
  updatedAt: number; // ms
  model?: string;
  totalTokens?: number;
  contextTokens?: number;
  origin?: SessionOrigin;
  status?: 'idle' | 'thinking' | 'typing';
};

export type SessionsListResponse = {
  count: number;
  sessions: SessionSummary[];
};

export type SessionDetail = SessionSummary & {
  inputTokens?: number;
  outputTokens?: number;
  abortedLastRun?: boolean;
  transcriptPath: string;
};

export type ChatRole = 'user' | 'assistant' | 'tool';

export type ChatMessage = {
  id: string;
  role: ChatRole;
  content: string;
  timestamp: string; // ISO8601
  metadata?: Record<string, unknown>;
  model?: string;
  tokens?: { input?: number; output?: number };
};

export type SessionsHistoryResponse = {
  messages: ChatMessage[];
  hasMore: boolean;
  nextCursor?: string;
};

export type SessionsDeleteResponse = {
  ok: true;
  deleted: {
    sessionKey: string;
    transcriptDeleted: boolean;
    messagesDeleted?: number;
  };
};

export type MessageAttachment = {
  type: 'image' | 'file' | 'audio';
  data: string; // base64
  filename: string;
  mimeType: string;
};

export type MessagesSendRequest = {
  sessionKey: string;
  message: string;
  attachments?: MessageAttachment[];
};

export type MessagesSendResponse = {
  ok: true;
  runId: string;
  status: 'accepted';
};

export type UploadDescriptor = {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
  url: string; // /api/uploads/:id
  expiresAt: string; // ISO8601
};

export type MessagesUploadResponse = UploadDescriptor;

export type AgentSummary = {
  id: string;
  name?: string;
  workspace?: string;
  identity?: { name: string; emoji?: string };
  model?: { primary: string };
};

export type AgentsListResponse = { agents: AgentSummary[] };

export type HealthResponse = {
  status: 'ok';
  timestamp: string;
  gateway: { connected: boolean; latency?: number };
  database: { connected: boolean };
};

export type StatusResponse = {
  version: string;
  uptime: number;
  gateway: { url: string; connected: boolean; protocol?: number };
  sessions: { active: number; total: number };
  users: { online: number; total: number };
};

// WebSocket protocol

export type WsClientInfo = {
  id: string; // e.g. "kleoz-web"
  instanceId: string; // stable per installation
  version: string;
  platform?: string;
  mode?: string;
  host?: string;
  ip?: string;
};

export type WsClientMessage =
  | { type: 'connect'; token: string; client?: WsClientInfo }
  | { type: 'subscribe'; sessionKeys: string[] }
  | { type: 'unsubscribe'; sessionKeys: string[] }
  | { type: 'subscribe.presence' }
  | { type: 'ping'; ts?: number };

export type WsConnectedEvent = { type: 'connected'; wsSessionId: string };

export type WsErrorEvent = {
  type: 'error';
  sessionKey?: string;
  runId?: string;
  error: ApiError;
};

export type WsMessageDeltaEvent = {
  type: 'message.delta';
  sessionKey: string;
  runId: string;
  delta: { content: string };
};

export type WsMessageCompleteEvent = {
  type: 'message.complete';
  sessionKey: string;
  runId: string;
  message: ChatMessage;
};

export type WsToolEvent = {
  type: 'tool.call' | 'tool.result';
  sessionKey: string;
  runId: string;
  tool: {
    id?: string;
    name: string;
    args?: Record<string, unknown>;
    status: 'running' | 'completed' | 'error';
    result?: unknown;
    error?: string;
  };
};

export type WsSessionEvent =
  | { type: 'session.created'; session: SessionSummary }
  | { type: 'session.updated'; sessionKey: string; changes: Partial<SessionSummary> }
  | { type: 'session.deleted'; sessionKey: string }
  | { type: 'session.status'; sessionKey: string; status: 'idle' | 'thinking' | 'typing' };

export type PresenceEntry = {
  instanceId: string;
  host: string;
  ip: string;
  version: string;
  platform?: string;
  deviceFamily?: string;
  modelIdentifier?: string;
  mode: string;
  roles?: string[];
  scopes?: string[];
  lastInputSeconds?: number;
  reason: string;
  ts: number;
};

export type WsPresenceEvent =
  | { type: 'presence.snapshot'; entries: PresenceEntry[]; stateVersion?: number }
  | { type: 'presence.updated'; entries: PresenceEntry[]; stateVersion: number }
  | { type: 'presence.joined'; entry: PresenceEntry }
  | { type: 'presence.left'; instanceId: string };

export type WsServerEvent =
  | WsConnectedEvent
  | WsErrorEvent
  | WsMessageDeltaEvent
  | WsMessageCompleteEvent
  | WsToolEvent
  | WsSessionEvent
  | WsPresenceEvent;

