import path from 'node:path';
import { randomUUID } from 'node:crypto';
import WebSocket from 'ws';
import { config } from '../config.js';
import { buildDeviceAuthPayload } from './deviceAuth.js';
import { loadOrCreateDeviceIdentity, publicKeyRawBase64UrlFromPem, signDevicePayload } from './deviceIdentity.js';

type GatewayFrame =
  | { type: 'req'; id: string; method: string; params?: unknown }
  | { type: 'res'; id: string; ok: boolean; payload?: unknown; error?: { code: string; message: string; details?: unknown } }
  | { type: 'event'; event: string; payload?: unknown; seq?: number };

export type OpenClawChatEvent = {
  runId: string;
  sessionKey: string;
  seq: number;
  state: 'delta' | 'final' | 'aborted' | 'error';
  message?: unknown;
  errorMessage?: string;
  usage?: unknown;
  stopReason?: string;
};

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function safeJsonParse(raw: string): any | null {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export class OpenClawGatewayClient {
  private ws: WebSocket | null = null;
  private closed = false;
  private backoffMs = 800;
  private pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private connectReqId: string | null = null;
  private connectNonce: string | null = null;
  private connectedAtMs: number | null = null;
  private lastLatencyMs: number | undefined;
  private helloProtocol: number | undefined;
  private instanceId = randomUUID();

  onChatEvent?: (evt: OpenClawChatEvent) => void;
  onClose?: (err: Error) => void;

  enabled(): boolean {
    return Boolean(config.gateway.token.trim() || config.gateway.password.trim());
  }

  connected(): boolean {
    return Boolean(this.ws && this.ws.readyState === WebSocket.OPEN && this.connectedAtMs);
  }

  protocol(): number | undefined {
    return this.helloProtocol;
  }

  latencyMs(): number | undefined {
    return this.lastLatencyMs;
  }

  uptimeSeconds(): number {
    if (!this.connectedAtMs) return 0;
    return Math.floor((Date.now() - this.connectedAtMs) / 1000);
  }

  start(): void {
    if (this.closed) this.closed = false;
    if (!this.enabled()) return;
    if (this.ws) return;
    this.connectLoop().catch(() => {});
  }

  stop(): void {
    this.closed = true;
    try {
      this.ws?.close();
    } catch {}
    this.ws = null;
    this.connectedAtMs = null;
    for (const [, p] of this.pending) p.reject(new Error('gateway client stopped'));
    this.pending.clear();
  }

  private async connectLoop(): Promise<void> {
    while (!this.closed) {
      try {
        await this.connectOnce();
        return;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        this.onClose?.(e);
        await sleep(this.backoffMs);
        this.backoffMs = Math.min(Math.floor(this.backoffMs * 1.7), 15_000);
      }
    }
  }

  private async connectOnce(): Promise<void> {
    const url = config.gateway.url;
    const ws = new WebSocket(url, { maxPayload: 25 * 1024 * 1024 });
    this.ws = ws;

    await new Promise<void>((resolve, reject) => {
      const onOpen = () => {
        cleanup();
        resolve();
      };
      const onError = (e: any) => {
        cleanup();
        reject(new Error(`gateway ws error: ${String(e?.message ?? e)}`));
      };
      const cleanup = () => {
        ws.removeEventListener('open', onOpen);
        ws.removeEventListener('error', onError);
      };
      ws.addEventListener('open', onOpen);
      ws.addEventListener('error', onError);
    });

    ws.addEventListener('message', (evt) => this.handleMessage(String((evt as any)?.data ?? '')));
    ws.addEventListener('close', (evt) => {
      const reason = String((evt as any)?.reason ?? '');
      const code = Number((evt as any)?.code ?? 1006);
      const err = new Error(`gateway closed (${code}): ${reason}`);
      this.ws = null;
      this.connectedAtMs = null;
      this.helloProtocol = undefined;
      for (const [, p] of this.pending) p.reject(err);
      this.pending.clear();
      if (!this.closed) {
        this.connectLoop().catch(() => {});
      }
    });

    // Queue initial connect shortly after open so we can handle connect.challenge nonce if present.
    await sleep(50);
    await this.sendConnect();

    // Reset backoff on successful connect.
    this.backoffMs = 800;

    // Light health pings to keep latency fresh.
    void this.healthPingLoop();
  }

  private async healthPingLoop(): Promise<void> {
    while (!this.closed && this.connected()) {
      try {
        const t0 = Date.now();
        await this.request('health', {});
        this.lastLatencyMs = Date.now() - t0;
      } catch {
        // ignore; close handler will reconnect if needed.
      }
      await sleep(30_000);
    }
  }

  private handleMessage(raw: string): void {
    const parsed = safeJsonParse(raw) as GatewayFrame | null;
    if (!parsed) return;
    if (parsed.type === 'event') {
      if (parsed.event === 'connect.challenge') {
        const nonce = (parsed.payload as any)?.nonce;
        if (typeof nonce === 'string' && nonce.trim()) {
          this.connectNonce = nonce.trim();
          // If connect is waiting, cancel it; sendConnect() will retry with the nonce.
          if (this.connectReqId) {
            const p = this.pending.get(this.connectReqId);
            if (p) {
              this.pending.delete(this.connectReqId);
              p.reject(new Error('connect challenged'));
            }
            this.connectReqId = null;
          }
        }
        return;
      }
      if (parsed.event === 'chat') {
        const payload = parsed.payload as any;
        if (payload && typeof payload.runId === 'string' && typeof payload.sessionKey === 'string') {
          const evt: OpenClawChatEvent = {
            runId: payload.runId,
            sessionKey: payload.sessionKey,
            seq: typeof payload.seq === 'number' ? payload.seq : 0,
            state: payload.state,
            message: payload.message,
            errorMessage: payload.errorMessage,
            usage: payload.usage,
            stopReason: payload.stopReason,
          };
          try {
            this.onChatEvent?.(evt);
          } catch {
            // ignore
          }
        }
        return;
      }
      return;
    }

    if (parsed.type === 'res') {
      const p = this.pending.get(parsed.id);
      if (!p) return;
      this.pending.delete(parsed.id);
      if (parsed.ok) p.resolve(parsed.payload);
      else p.reject(new Error(parsed.error?.message ?? 'gateway error'));
    }
  }

  private async sendConnect(): Promise<void> {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) throw new Error('gateway not connected');
    if (this.connectedAtMs) return;

    const token = config.gateway.token.trim();
    const password = config.gateway.password.trim();
    const scopes = ['operator.admin'];
    const role = 'operator';
    const clientId = 'kleoz-backend';
    const clientMode = 'backend';
    const signedAtMs = Date.now();

    const identityPath = path.resolve(config.dataDir, 'openclaw-device.json');
    const identity = loadOrCreateDeviceIdentity(identityPath);
    const nonce = this.connectNonce ?? undefined;
    const payload = buildDeviceAuthPayload({
      deviceId: identity.deviceId,
      clientId,
      clientMode,
      role,
      scopes,
      signedAtMs,
      token: token || null,
      nonce,
    });
    const signature = signDevicePayload(identity.privateKeyPem, payload);
    const device = {
      id: identity.deviceId,
      publicKey: publicKeyRawBase64UrlFromPem(identity.publicKeyPem),
      signature,
      signedAt: signedAtMs,
      nonce,
    };

    // connect can be challenged with a nonce; retry in-place without reconnecting the socket.
    for (;;) {
      const reqId = randomUUID();
      this.connectReqId = reqId;
      const frame: GatewayFrame = {
        type: 'req',
        id: reqId,
        method: 'connect',
        params: {
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            id: clientId,
            displayName: 'kleoz',
            version: config.version,
            platform: process.platform,
            mode: clientMode,
            instanceId: this.instanceId,
          },
          role,
          scopes,
          device,
          auth: token || password ? { token: token || undefined, password: password || undefined } : undefined,
        },
      };

      try {
        const hello = await this.sendAndWait(frame);
        const protocol = (hello as any)?.protocol;
        if (typeof protocol !== 'number') throw new Error('invalid hello');
        this.helloProtocol = protocol;
        this.connectedAtMs = Date.now();
        return;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'connect challenged') {
          // nonce should now be set via the event handler; retry.
          await sleep(10);
          continue;
        }
        throw err;
      } finally {
        if (this.connectReqId === reqId) this.connectReqId = null;
      }
    }
  }

  private sendAndWait(frame: GatewayFrame): Promise<unknown> {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return Promise.reject(new Error('gateway not connected'));
    if (frame.type !== 'req') return Promise.reject(new Error('invalid frame'));
    return new Promise<unknown>((resolve, reject) => {
      this.pending.set(frame.id, { resolve, reject });
      try {
        ws.send(JSON.stringify(frame));
      } catch (err) {
        this.pending.delete(frame.id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  async request<TPayload = unknown>(method: string, params?: unknown): Promise<TPayload> {
    if (!this.enabled()) throw new Error('gateway disabled');
    if (!this.ws) this.start();
    // Wait for connection, but don't hang forever.
    const t0 = Date.now();
    while (!this.connected()) {
      if (Date.now() - t0 > 10_000) throw new Error('gateway connect timeout');
      await sleep(50);
    }
    const req: GatewayFrame = { type: 'req', id: randomUUID(), method, params };
    const payload = await this.sendAndWait(req);
    return payload as TPayload;
  }
}
