import type {
  ApiError,
  ApiErrorResponse,
  AuthLoginRequest,
  AuthLoginResponse,
  AuthLogoutResponse,
  MessagesSendRequest,
  MessagesSendResponse,
  MessagesUploadResponse,
  PresenceEntry,
  SessionsHistoryResponse,
  SessionsListResponse,
  UserMe,
} from '@kleoz/contracts';

import { encodeSessionKey } from './encode';

export class ApiRequestError extends Error {
  readonly status: number;
  readonly apiError: ApiError;
  constructor(status: number, apiError: ApiError) {
    super(apiError.message);
    this.name = 'ApiRequestError';
    this.status = status;
    this.apiError = apiError;
  }
}

async function readJsonSafe(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

function getErrorFromPayload(payload: unknown): ApiError | null {
  const maybe = payload as ApiErrorResponse | null;
  if (!maybe?.error?.code || !maybe?.error?.message) return null;
  return maybe.error;
}

export async function apiFetchJson<T>(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<T> {
  const { token, headers, ...rest } = init;
  const res = await fetch(path, {
    ...rest,
    headers: {
      ...(headers ?? {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!res.ok) {
    const payload = await readJsonSafe(res);
    const apiError =
      getErrorFromPayload(payload) ??
      ({
        code: 'GATEWAY_UNAVAILABLE',
        message: `Request failed (${res.status})`,
        details: { path },
      } satisfies ApiError);
    throw new ApiRequestError(res.status, apiError);
  }

  const out = (await readJsonSafe(res)) as T;
  return out;
}

export async function login(req: AuthLoginRequest): Promise<AuthLoginResponse> {
  return apiFetchJson<AuthLoginResponse>('/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
}

export async function logout(token: string): Promise<AuthLogoutResponse> {
  return apiFetchJson<AuthLogoutResponse>('/api/auth/logout', {
    method: 'POST',
    token,
  });
}

export async function getMe(token: string): Promise<UserMe> {
  return apiFetchJson<UserMe>('/api/auth/me', { token });
}

export async function listSessions(token: string, limit = 50): Promise<SessionsListResponse> {
  const url = new URL('/api/sessions', window.location.origin);
  url.searchParams.set('limit', String(limit));
  return apiFetchJson<SessionsListResponse>(url.pathname + url.search, { token });
}

export async function getHistory(
  token: string,
  sessionKey: string,
  opts: { limit?: number; includeTools?: boolean; before?: string } = {},
): Promise<SessionsHistoryResponse> {
  const url = new URL(`/api/sessions/${encodeSessionKey(sessionKey)}/history`, window.location.origin);
  url.searchParams.set('limit', String(opts.limit ?? 100));
  if (opts.includeTools) url.searchParams.set('includeTools', 'true');
  if (opts.before) url.searchParams.set('before', opts.before);
  return apiFetchJson<SessionsHistoryResponse>(url.pathname + url.search, { token });
}

export async function sendMessage(token: string, req: MessagesSendRequest): Promise<MessagesSendResponse> {
  return apiFetchJson<MessagesSendResponse>('/api/messages/send', {
    method: 'POST',
    token,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
}

export async function uploadMessageFile(token: string, file: File): Promise<MessagesUploadResponse> {
  const fd = new FormData();
  fd.append('file', file);
  return apiFetchJson<MessagesUploadResponse>('/api/messages/upload', {
    method: 'POST',
    token,
    body: fd,
  });
}

export type PresenceGetResponse = {
  entries: PresenceEntry[];
  gatewayUptime: number;
  timestamp: number;
};

export async function getPresence(token: string): Promise<PresenceGetResponse> {
  return apiFetchJson<PresenceGetResponse>('/api/presence', { token });
}

