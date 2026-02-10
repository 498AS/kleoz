import type { WebSocket } from 'ws';

interface SocketMeta {
  userId: string;
  username: string;
  agentId: string;
  subscriptions: Set<string>;
}

interface PresenceEvent {
  type: 'presence.snapshot' | 'presence.joined' | 'presence.left';
  users?: string[];
  username?: string;
}

export class RealtimeHub {
  private sockets = new Map<WebSocket, SocketMeta>();

  register(ws: WebSocket, meta: Omit<SocketMeta, 'subscriptions'>): void {
    this.sockets.set(ws, { ...meta, subscriptions: new Set() });
    this.broadcastPresence({ type: 'presence.joined', username: meta.username });
    ws.send(JSON.stringify({ type: 'presence.snapshot', users: this.onlineUsers() } satisfies PresenceEvent));
  }

  unregister(ws: WebSocket): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    this.sockets.delete(ws);
    this.broadcastPresence({ type: 'presence.left', username: meta.username });
  }

  setSubscriptions(ws: WebSocket, sessionKeys: string[]): void {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    meta.subscriptions = new Set(sessionKeys);
  }

  emitToSession(sessionKey: string, event: object): void {
    for (const [socket, meta] of this.sockets.entries()) {
      if (meta.subscriptions.has(sessionKey)) {
        socket.send(JSON.stringify(event));
      }
    }
  }

  private onlineUsers(): string[] {
    return Array.from(new Set(Array.from(this.sockets.values()).map((s) => s.username)));
  }

  private broadcastPresence(event: PresenceEvent): void {
    for (const socket of this.sockets.keys()) {
      socket.send(JSON.stringify(event));
    }
  }
}
