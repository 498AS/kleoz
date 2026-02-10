import type { PresenceEntry, WsServerEvent } from '@kleoz/contracts';
import type { JwtClaims } from './jwt.js';
import type { ServerWebSocket } from 'bun';

type WsData = { claims: JwtClaims };

type SocketMeta = {
  wsSessionId: string;
  userId: string;
  username: string;
  agentId: string;
  subscriptions: Set<string>;
  wantsPresence: boolean;
  presence?: PresenceEntry;
};

export class RealtimeHub {
  private sockets = new Map<ServerWebSocket<WsData>, SocketMeta>();
  private presenceVersion = 0;

  register(ws: ServerWebSocket<WsData>): SocketMeta {
    const claims = ws.data.claims;
    const meta: SocketMeta = {
      wsSessionId: crypto.randomUUID(),
      userId: claims.sub,
      username: claims.username,
      agentId: claims.agentId,
      subscriptions: new Set(),
      wantsPresence: false,
    };
    this.sockets.set(ws, meta);

    // Send connected handshake immediately.
    this.send(ws, { type: 'connected', wsSessionId: meta.wsSessionId });
    return meta;
  }

  unregister(ws: ServerWebSocket<WsData>): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    this.sockets.delete(ws);
    if (meta.presence) this.broadcastPresence({ type: 'presence.left', instanceId: meta.presence.instanceId });
  }

  setSubscriptions(ws: ServerWebSocket<WsData>, sessionKeys: string[]): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    meta.subscriptions = new Set(sessionKeys);
  }

  subscribe(ws: ServerWebSocket<WsData>, sessionKeys: string[]): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    for (const k of sessionKeys) meta.subscriptions.add(k);
  }

  unsubscribe(ws: ServerWebSocket<WsData>, sessionKeys: string[]): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    for (const k of sessionKeys) meta.subscriptions.delete(k);
  }

  subscribePresence(ws: ServerWebSocket<WsData>): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    meta.wantsPresence = true;
    this.send(ws, { type: 'presence.snapshot', entries: this.presenceEntries(), stateVersion: this.presenceVersion });
  }

  getPresenceSnapshot(): { entries: PresenceEntry[]; stateVersion: number } {
    return { entries: this.presenceEntries(), stateVersion: this.presenceVersion };
  }

  updatePresenceFromClientInfo(
    ws: ServerWebSocket<WsData>,
    client: {
      instanceId?: string;
      version?: string;
      platform?: string;
      mode?: string;
      host?: string;
      ip?: string;
    },
  ): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;

    const now = Date.now();
    const entry: PresenceEntry = {
      instanceId: String(client.instanceId || meta.wsSessionId),
      host: String(client.host || ''),
      ip: String(client.ip || ''),
      version: String(client.version || ''),
      platform: client.platform,
      mode: String(client.mode || 'webchat'),
      reason: 'connect',
      ts: now,
    };

    const had = Boolean(meta.presence);
    meta.presence = entry;
    this.presenceVersion += 1;
    this.broadcastPresence(had ? { type: 'presence.updated', entries: [entry], stateVersion: this.presenceVersion } : { type: 'presence.joined', entry });
  }

  emitToSession(sessionKey: string, event: WsServerEvent): void {
    for (const [socket, meta] of this.sockets.entries()) {
      if (meta.subscriptions.has(sessionKey)) this.send(socket, event);
    }
  }

  broadcast(event: WsServerEvent): void {
    for (const socket of this.sockets.keys()) this.send(socket, event);
  }

  private broadcastPresence(event: WsServerEvent): void {
    for (const [socket, meta] of this.sockets.entries()) {
      if (!meta.wantsPresence) continue;
      this.send(socket, event);
    }
  }

  private presenceEntries(): PresenceEntry[] {
    return Array.from(this.sockets.values())
      .map((m) => m.presence)
      .filter((e): e is PresenceEntry => Boolean(e));
  }

  private send(ws: ServerWebSocket<WsData>, ev: WsServerEvent): void {
    try {
      ws.send(JSON.stringify(ev));
    } catch {
      // Ignore send errors; close handler will clean up.
    }
  }
}
