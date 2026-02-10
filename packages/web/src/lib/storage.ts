const AUTH_KEY = 'kleoz.auth';
const INSTANCE_ID_KEY = 'kleoz.instanceId';

export type StoredAuth = {
  token: string;
  expiresAt: string; // ISO8601
  user: { id: string; username: string; agentId: string; role: 'admin' | 'user'; createdAt: string };
};

export function loadAuth(): StoredAuth | null {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredAuth;
    if (!parsed?.token || !parsed?.expiresAt || !parsed?.user?.id) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveAuth(auth: StoredAuth): void {
  localStorage.setItem(AUTH_KEY, JSON.stringify(auth));
}

export function clearAuth(): void {
  localStorage.removeItem(AUTH_KEY);
}

export function getOrCreateInstanceId(): string {
  const existing = localStorage.getItem(INSTANCE_ID_KEY);
  if (existing) return existing;
  const id = crypto.randomUUID();
  localStorage.setItem(INSTANCE_ID_KEY, id);
  return id;
}

