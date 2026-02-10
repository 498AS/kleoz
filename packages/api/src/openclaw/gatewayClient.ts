export type GatewayFrame =
  | { type: 'req'; id: string; method: string; params?: unknown }
  | {
      type: 'res';
      id: string;
      ok: boolean;
      payload?: unknown;
      error?: { code: string; message: string; details?: unknown };
    }
  | { type: 'event'; event: string; payload?: unknown; seq?: number };

export type GatewayConnectParams = {
  minProtocol: number;
  maxProtocol: number;
  client: {
    id: string;
    displayName?: string;
    version: string;
    platform: string;
    mode: string;
    instanceId?: string;
  };
  auth?: { token?: string; password?: string };
  role?: 'operator' | 'node';
  scopes?: Array<string>;
};

type Pending = {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

export class OpenClawGatewayClient {
  private ws: WebSocket | null = null;
  private connected = false;
  private connectPromise: Promise<void> | null = null;
  private pending = new Map<string, Pending>();
  private listeners = new Set<(frame: Extract<GatewayFrame, { type: 'event' }>) => void>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempt = 0;
  private lastLatencyMs: number | undefined;

  constructor(
    private readonly cfg: {
      url: string;
      token?: string;
      password?: string;
      minProtocol: number;
      maxProtocol: number;
      client: { id: string; displayName?: string; version: string; platform: string; mode: string; instanceId: string };
    },
  ) {}

  isConnected(): boolean {
    return this.connected;
  }

  getLatencyMs(): number | undefined {
    return this.lastLatencyMs;
  }

  onEvent(cb: (frame: Extract<GatewayFrame, { type: 'event' }>) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  start(): void {
    void this.ensureConnected();
  }

  async waitForConnected(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.connected) return;
      await this.ensureConnected().catch(() => null);
      if (this.connected) return;
      await new Promise((r) => setTimeout(r, 150));
    }
    throw new Error('Gateway connection timeout');
  }

  async rpc<TPayload = unknown>(method: string, params?: unknown, timeoutMs = 120_000): Promise<TPayload> {
    await this.ensureConnected();
    if (!this.ws || !this.connected) throw new Error('Gateway not connected');

    const id = crypto.randomUUID();
    const req: GatewayFrame = { type: 'req', id, method, params };
    const ws = this.ws;
    const t0 = Date.now();

    const payload = await new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Gateway RPC timeout: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timeout });
      ws.send(JSON.stringify(req));
    });

    this.lastLatencyMs = Date.now() - t0;
    return payload as TPayload;
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected && this.ws && this.ws.readyState === WebSocket.OPEN) return;
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = this.connectOnce().finally(() => {
      this.connectPromise = null;
    });
    return this.connectPromise;
  }

  private async connectOnce(): Promise<void> {
    if (!this.cfg.token && !this.cfg.password) {
      throw new Error('Missing OpenClaw auth. Set OPENCLAW_GATEWAY_TOKEN or OPENCLAW_GATEWAY_PASSWORD.');
    }

    // Clean up any previous socket.
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // ignore
      }
    }

    const ws = new WebSocket(this.cfg.url);
    this.ws = ws;
    this.connected = false;

    const opened = await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error('Gateway WS error'));
    });
    void opened;

    ws.onmessage = (evt) => this.handleMessage(String(evt.data));
    ws.onclose = () => this.handleClose();

    // connect handshake must be first request
    const connectId = crypto.randomUUID();
    const params: GatewayConnectParams = {
      minProtocol: this.cfg.minProtocol,
      maxProtocol: this.cfg.maxProtocol,
      client: this.cfg.client,
      auth: {
        token: this.cfg.token || undefined,
        password: this.cfg.password || undefined,
      },
      role: 'operator',
      scopes: ['operator.admin'],
    };

    const connectReq: GatewayFrame = { type: 'req', id: connectId, method: 'connect', params };
    await new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(connectId);
        reject(new Error('Gateway connect timeout'));
      }, 10_000);
      this.pending.set(connectId, { resolve, reject, timeout });
      ws.send(JSON.stringify(connectReq));
    });

    this.connected = true;
    this.reconnectAttempt = 0;
  }

  private handleClose(): void {
    this.connected = false;
    // Reject pending waiters.
    for (const [id, p] of this.pending.entries()) {
      clearTimeout(p.timeout);
      p.reject(new Error('Gateway disconnected'));
      this.pending.delete(id);
    }
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectAttempt += 1;
    const base = 500;
    const max = 10_000;
    const delay = Math.min(max, base * 2 ** Math.min(5, this.reconnectAttempt));
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.ensureConnected().catch(() => this.scheduleReconnect());
    }, delay);
  }

  private handleMessage(raw: string): void {
    let parsed: GatewayFrame | null = null;
    try {
      parsed = JSON.parse(raw) as GatewayFrame;
    } catch {
      return;
    }
    if (!parsed) return;

    if (parsed.type === 'res') {
      const p = this.pending.get(parsed.id);
      if (!p) return;
      this.pending.delete(parsed.id);
      clearTimeout(p.timeout);
      if (parsed.ok) p.resolve(parsed.payload);
      else p.reject(new Error(parsed.error?.message ?? 'gateway error'));
      return;
    }

    if (parsed.type === 'event') {
      for (const cb of this.listeners) {
        try {
          cb(parsed);
        } catch {
          // ignore
        }
      }
    }
  }
}
