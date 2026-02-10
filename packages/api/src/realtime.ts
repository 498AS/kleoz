import type { PresenceEntry } from './types.js';

interface SocketMeta {
  userId: string;
  username: string;
  agentId: string;
  subscriptions: Set<string>;
  presenceEnabled: boolean;
  instanceId: string;
  connectedAt: number;
  lastInputAt: number;
}

export type HubSocket = {
  send: (data: string) => unknown;
};

export class RealtimeHub {
  private sockets = new Map<HubSocket, SocketMeta>();

  register(ws: HubSocket, meta: Pick<SocketMeta, 'userId' | 'username' | 'agentId'>): void {
    const now = Date.now();
    this.sockets.set(ws, { ...meta, subscriptions: new Set(), presenceEnabled: false, instanceId: crypto.randomUUID(), connectedAt: now, lastInputAt: now });
  }

  unregister(ws: HubSocket): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    this.sockets.delete(ws);
    this.broadcastPresenceLeft(meta.instanceId);
  }

  setSubscriptions(ws: HubSocket, sessionKeys: string[]): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    meta.subscriptions = new Set(sessionKeys);
  }

  removeSubscriptions(ws: HubSocket, sessionKeys: string[]): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    for (const k of sessionKeys) meta.subscriptions.delete(k);
  }

  enablePresence(ws: HubSocket): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    meta.presenceEnabled = true;
    ws.send(JSON.stringify({ type: 'presence.snapshot', entries: this.presenceEntries(), stateVersion: Date.now() }));
    this.broadcastPresenceJoined(meta);
  }

  updateClient(ws: HubSocket, client: { instanceId?: string; version?: string; platform?: string; mode?: string }): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    if (client.instanceId && typeof client.instanceId === 'string') {
      meta.instanceId = client.instanceId;
    }
  }

  noteInput(ws: HubSocket): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    meta.lastInputAt = Date.now();
  }

  emitToSession(sessionKey: string, event: object): void {
    for (const [socket, meta] of this.sockets.entries()) {
      if (meta.subscriptions.has(sessionKey)) {
        socket.send(JSON.stringify(event));
      }
    }
  }

  emitToAgent(agentId: string, event: object): void {
    for (const [socket, meta] of this.sockets.entries()) {
      if (meta.agentId === agentId) {
        socket.send(JSON.stringify(event));
      }
    }
  }

  onlineUserCount(): number {
    return new Set(Array.from(this.sockets.values()).map((s) => s.userId)).size;
  }

  presenceEntries(): PresenceEntry[] {
    const now = Date.now();
    return Array.from(this.sockets.values()).map((m) => ({
      instanceId: m.instanceId,
      host: 'unknown',
      ip: 'unknown',
      version: '0.1.0',
      platform: 'web',
      mode: 'webchat',
      reason: 'connect',
      lastInputSeconds: Math.floor((now - m.lastInputAt) / 1000),
      ts: m.lastInputAt,
    }));
  }

  private broadcastPresenceJoined(meta: SocketMeta): void {
    const entry = this.presenceEntries().find((e) => e.instanceId === meta.instanceId);
    if (!entry) return;
    for (const [socket, m] of this.sockets.entries()) {
      if (!m.presenceEnabled) continue;
      socket.send(JSON.stringify({ type: 'presence.joined', entry }));
    }
  }

  private broadcastPresenceLeft(instanceId: string): void {
    for (const [socket, m] of this.sockets.entries()) {
      if (!m.presenceEnabled) continue;
      socket.send(JSON.stringify({ type: 'presence.left', instanceId }));
    }
  }
}
