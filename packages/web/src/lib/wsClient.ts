import type { ApiError, WsClientInfo, WsClientMessage, WsServerEvent } from '@kleoz/contracts';

export type WsStatus = 'idle' | 'connecting' | 'open' | 'closed' | 'error';

export type WsClientState = {
  status: WsStatus;
  wsSessionId?: string;
  lastError?: ApiError;
  lastConnectedAt?: number;
};

type Handlers = {
  onState: (state: WsClientState) => void;
  onEvent: (event: WsServerEvent) => void;
};

function wsUrlFromWindow(token: string): string {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${wsProtocol}//${window.location.host}/api/ws?token=${encodeURIComponent(token)}`;
}

export class WsClient {
  private ws: WebSocket | null = null;
  private readonly token: string;
  private readonly clientInfo?: WsClientInfo;
  private readonly handlers: Handlers;
  private reconnectAttempts = 0;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private desiredSessionKeys = new Set<string>();
  private wantsPresence = false;
  private closedByUser = false;
  private state: WsClientState = { status: 'idle' };
  private sendQueue: string[] = [];

  constructor(args: { token: string; clientInfo?: WsClientInfo; handlers: Handlers }) {
    this.token = args.token;
    this.clientInfo = args.clientInfo;
    this.handlers = args.handlers;
  }

  connect(): void {
    this.closedByUser = false;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;
    this.clearReconnectTimer();
    this.setState({ status: 'connecting', lastError: undefined });

    const ws = new WebSocket(wsUrlFromWindow(this.token));
    this.ws = ws;

    ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.setState({ status: 'open', lastError: undefined, lastConnectedAt: Date.now() });

      // Optional connect message (contract supports it).
      const connectMsg: WsClientMessage = { type: 'connect', token: this.token, client: this.clientInfo };
      this.send(connectMsg);

      this.flushQueue();
      this.resubscribeAll();
      this.startPing();
    };

    ws.onclose = () => {
      this.stopPing();
      this.setState({ status: 'closed', wsSessionId: undefined });
      if (!this.closedByUser) this.scheduleReconnect();
    };

    ws.onerror = () => {
      this.setState({ status: 'error' });
      // onclose will handle reconnect.
    };

    ws.onmessage = (evt) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(evt.data));
      } catch {
        return;
      }
      const event = parsed as WsServerEvent;
      if (event?.type === 'connected') {
        this.setState({ wsSessionId: (event as { wsSessionId: string }).wsSessionId });
      }
      if (event?.type === 'error') {
        this.setState({ lastError: (event as { error: ApiError }).error });
      }
      this.handlers.onEvent(event);
    };
  }

  close(): void {
    this.closedByUser = true;
    this.clearReconnectTimer();
    this.stopPing();
    const ws = this.ws;
    this.ws = null;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) ws.close();
    this.setState({ status: 'closed', wsSessionId: undefined });
  }

  setDesiredSubscriptions(sessionKeys: string[]): void {
    const next = new Set(sessionKeys);

    // Diff + minimize chatter.
    const toUnsub: string[] = [];
    const toSub: string[] = [];
    for (const k of this.desiredSessionKeys) if (!next.has(k)) toUnsub.push(k);
    for (const k of next) if (!this.desiredSessionKeys.has(k)) toSub.push(k);

    this.desiredSessionKeys = next;

    if (toUnsub.length) this.send({ type: 'unsubscribe', sessionKeys: toUnsub });
    if (toSub.length) this.send({ type: 'subscribe', sessionKeys: toSub });
  }

  enablePresenceSubscription(enabled: boolean): void {
    this.wantsPresence = enabled;
    if (enabled) this.send({ type: 'subscribe.presence' });
  }

  send(msg: WsClientMessage): void {
    const raw = JSON.stringify(msg);
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      this.sendQueue.push(raw);
      return;
    }
    ws.send(raw);
  }

  private flushQueue(): void {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const q = this.sendQueue;
    this.sendQueue = [];
    for (const raw of q) ws.send(raw);
  }

  private resubscribeAll(): void {
    if (this.desiredSessionKeys.size) {
      this.send({ type: 'subscribe', sessionKeys: Array.from(this.desiredSessionKeys) });
    }
    if (this.wantsPresence) this.send({ type: 'subscribe.presence' });
  }

  private scheduleReconnect(): void {
    this.clearReconnectTimer();
    this.reconnectAttempts += 1;
    const base = 500;
    const max = 8000;
    const delay = Math.min(max, base * 2 ** Math.min(5, this.reconnectAttempts));
    this.reconnectTimer = window.setTimeout(() => this.connect(), delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer != null) window.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = window.setInterval(() => {
      this.send({ type: 'ping', ts: Date.now() });
    }, 25_000);
  }

  private stopPing(): void {
    if (this.pingTimer != null) window.clearInterval(this.pingTimer);
    this.pingTimer = null;
  }

  private setState(patch: Partial<WsClientState>): void {
    this.state = { ...this.state, ...patch };
    this.handlers.onState(this.state);
  }
}

