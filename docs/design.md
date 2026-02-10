# Design Document — kleoz

> Especificación técnica y decisiones de diseño.

## Resumen Ejecutivo

**kleoz** es una interfaz web multi-agente para OpenClaw que permite:

- Autenticación por agente (cada usuario ve solo sus sesiones)
- Multi-tasking real (múltiples chats en paralelo)
- Sincronización total con OpenClaw (JSONL como fuente de verdad)
- Soporte multimedia completo

---

## Decisiones de Diseño

### 1. Arquitectura Híbrida

**Decisión:** Backend propio (Hono) + delegación a OpenClaw.

**Razón:**
- kleoz maneja auth/usuarios/UI, pero no duplica lógica de agentes
- OpenClaw ya tiene todo el runtime de agentes
- Separación de responsabilidades clara

**Alternativas descartadas:**
- Standalone con propio runtime → duplicación innecesaria
- Solo frontend directo a Gateway → no permite auth por usuario

---

### 2. SQLite para Persistencia Local

**Decisión:** SQLite para usuarios y cache.

**Razón:**
- Zero-config, embebido, sin dependencias externas
- Suficiente para el volumen esperado
- Fácil de hacer backup junto con OpenClaw
- Deploy en mismo servidor que OpenClaw

**No usamos SQLite para:**
- Historial de mensajes → JSONL de OpenClaw es la fuente
- Estado de sesiones → OpenClaw Gateway es la fuente

---

### 3. WebSocket Multiplexado

**Decisión:** Una conexión WS por cliente, múltiples suscripciones.

**Razón:**
- Eficiente en recursos
- El cliente abre N sesiones pero mantiene 1 socket
- Gateway ya soporta este patrón

```
Cliente ─────[1 WebSocket]────► kleoz API ────► OpenClaw Gateway
                                    │
                                    ├── Suscripción: session:A
                                    ├── Suscripción: session:B
                                    └── Suscripción: session:C
```

---

### 4. TanStack Router (no React Router)

**Decisión:** TanStack Router para routing.

**Razón:**
- Type-safe end-to-end
- File-based routing moderno
- Mejor integración con TanStack Query
- Loaders y data fetching integrado

---

### 5. Shadcn/ui (no librería de componentes)

**Decisión:** Shadcn/ui con Tailwind.

**Razón:**
- Componentes copiables, no dependencia
- Totalmente customizable
- Accesibilidad incluida (Radix primitives)
- No lock-in a una librería

---

### 6. JWT Stateless Auth

**Decisión:** JWT sin sesiones server-side.

**Razón:**
- Escalabilidad (no state en servidor)
- Simplicidad
- Compatible con múltiples tabs/dispositivos

**Mitigaciones:**
- Expiración razonable (7 días)
- Revocación via blacklist (futuro)

---

## Flujos Principales

### Login Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Browser │────►│ kleoz   │────►│ SQLite  │
│         │     │ API     │     │         │
└─────────┘     └─────────┘     └─────────┘
     │               │               │
     │ POST /login   │               │
     │──────────────►│               │
     │               │ SELECT user   │
     │               │──────────────►│
     │               │◄──────────────│
     │               │               │
     │               │ bcrypt.verify │
     │               │               │
     │               │ JWT.sign      │
     │◄──────────────│               │
     │ { token }     │               │
```

### Message Send Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│ Browser │────►│ kleoz   │────►│ OpenClaw│────►│  Agent  │
│         │     │ API     │     │ Gateway │     │ Runtime │
└─────────┘     └─────────┘     └─────────┘     └─────────┘
     │               │               │               │
     │ WS: send      │               │               │
     │──────────────►│               │               │
     │               │ sessions_send │               │
     │               │──────────────►│               │
     │               │               │ run agent     │
     │               │               │──────────────►│
     │               │               │               │
     │               │◄─ streaming ──│◄─ streaming ──│
     │◄─ streaming ──│               │               │
```

### Session Sync Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Browser │◄───►│ kleoz   │◄───►│ OpenClaw│
│         │     │ API     │     │ Gateway │
└─────────┘     └─────────┘     └─────────┘
     │               │               │
     │ WS: subscribe │               │
     │──────────────►│               │
     │               │ sessions_list │
     │               │──────────────►│
     │               │◄──────────────│
     │◄──────────────│               │
     │ initial state │               │
     │               │               │
     │               │◄── events ────│
     │◄── events ────│               │
     │ real-time     │               │
```

---

## Modelo de Datos

### Usuario

```typescript
interface User {
  id: string;           // UUID
  username: string;     // Único
  passwordHash: string; // bcrypt
  agentId: string;      // Agente asignado
  role: 'admin' | 'user';
  createdAt: number;
  updatedAt: number;
  lastLoginAt?: number;
  settings?: UserSettings;
}

interface UserSettings {
  theme?: 'light' | 'dark' | 'system';
  notifications?: boolean;
  soundEnabled?: boolean;
}
```

### Sesión (Cache)

```typescript
// Cache local de sesiones de OpenClaw
interface SessionCache {
  key: string;          // session key
  data: Session;        // datos de OpenClaw
  cachedAt: number;
  expiresAt: number;
}

interface Session {
  key: string;
  sessionId: string;
  kind: 'dm' | 'group' | 'channel';
  channel: string;
  displayName?: string;
  updatedAt: number;
  model: string;
  totalTokens: number;
  contextTokens: number;
}
```

### Mensaje

```typescript
// Mensajes vienen de OpenClaw, no se persisten en kleoz
interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
  metadata?: {
    channel?: string;
    from?: string;
    model?: string;
    tokens?: { input: number; output: number };
    tools?: ToolCall[];
  };
}

interface ToolCall {
  id: string;
  name: string;
  args: Record<string, unknown>;
  status: 'running' | 'completed' | 'error';
  result?: unknown;
  error?: string;
}
```

---

## Consideraciones de Escala

### Límites Actuales (OpenClaw)

| Recurso | Límite |
|---------|--------|
| Sesiones concurrentes por agente | 4 |
| Subagentes concurrentes | 8 |
| Context tokens (Opus) | 200,000 |

### Proyecciones kleoz

| Escenario | Usuarios | Sesiones | WebSocket |
|-----------|----------|----------|-----------|
| Pequeño | 1-5 | 10-50 | 5 |
| Mediano | 5-20 | 50-200 | 20 |
| Grande | 20-50 | 200-500 | 50 |

### Optimizaciones Planificadas

1. **Virtualización de listas** — TanStack Virtual para historiales largos
2. **Debounce de eventos** — Agrupar updates de presence
3. **Cache agresivo** — TanStack Query con staleTime apropiado
4. **Lazy loading** — Cargar historiales por página

---

## Seguridad

Ver [security.md](security.md) para detalles completos.

### Resumen

- Auth: JWT con bcrypt
- Aislamiento: Por agente
- Rate limiting: Por endpoint
- Headers: CSP, HSTS, etc.
- Audit: Logging de acciones

---

## Testing Strategy

### Unit Tests

```typescript
// Vitest para lógica de negocio
describe('UserService', () => {
  it('should hash password correctly', async () => {
    const hash = await hashPassword('test123');
    expect(await verifyPassword('test123', hash)).toBe(true);
  });
});
```

### Integration Tests

```typescript
// Tests de API con Hono test client
describe('POST /api/auth/login', () => {
  it('should return token for valid credentials', async () => {
    const res = await app.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: 'test123' }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toHaveProperty('token');
  });
});
```

### E2E Tests (Futuro)

- Playwright para flujos completos
- Mock de OpenClaw Gateway

---

## Deployment

### Requisitos

- Node.js 22+
- OpenClaw Gateway en el mismo servidor
- Puerto 3000 (configurable)
- ~100MB RAM
- ~50MB disco (sin contar uploads)

### Docker

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY . .
RUN npm ci && npm run build
EXPOSE 3000
CMD ["node", "dist/api/index.js"]
```

### Variables de Entorno

```bash
PORT=3000
NODE_ENV=production
JWT_SECRET=<random-64-chars>
OPENCLAW_GATEWAY_URL=ws://localhost:18789
OPENCLAW_GATEWAY_TOKEN=<gateway-token>
DATABASE_PATH=./data/kleoz.db
```

---

## Próximos Pasos

1. **Scaffolding** — Crear estructura de monorepo
2. **Auth básico** — Login/logout/JWT
3. **Gateway client** — Conexión a OpenClaw
4. **Session list** — Primera vista funcional
5. **Chat UI** — Envío/recepción de mensajes

---

## Referencias

- [OpenClaw Documentation](https://docs.openclaw.ai)
- [OpenClaw Gateway Protocol](https://docs.openclaw.ai/gateway/protocol)
- [TanStack Router](https://tanstack.com/router)
- [Hono](https://hono.dev)
- [Shadcn/ui](https://ui.shadcn.com)
