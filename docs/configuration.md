# Configuración — kleoz

> Guía completa de configuración de kleoz y su integración con OpenClaw.

## Estructura del Proyecto

```
kleoz/
├── packages/
│   ├── api/                    # Backend Hono
│   │   ├── src/
│   │   │   ├── routes/         # Endpoints REST
│   │   │   ├── ws/             # WebSocket handlers
│   │   │   ├── middleware/     # Auth, logging, etc.
│   │   │   ├── services/       # Lógica de negocio
│   │   │   ├── db/             # SQLite schemas
│   │   │   └── gateway/        # Cliente OpenClaw
│   │   └── package.json
│   │
│   └── web/                    # Frontend React
│       ├── src/
│       │   ├── routes/         # TanStack Router
│       │   ├── components/     # UI components
│       │   ├── hooks/          # Custom hooks
│       │   ├── stores/         # Zustand stores
│       │   └── lib/            # Utilities
│       └── package.json
│
├── docker-compose.yml
├── kleoz.config.ts             # Configuración central
└── package.json
```

---

## Configuración Central

### `kleoz.config.ts`

```typescript
import { defineConfig } from '@kleoz/config';

export default defineConfig({
  // === Servidor ===
  server: {
    port: 3000,
    host: '0.0.0.0',
  },

  // === Base de datos ===
  database: {
    path: './data/kleoz.db',
    // Opciones SQLite
    pragma: {
      journal_mode: 'WAL',
      synchronous: 'NORMAL',
    },
  },

  // === OpenClaw Gateway ===
  gateway: {
    url: 'ws://localhost:18789',
    token: process.env.OPENCLAW_GATEWAY_TOKEN,
    // Reconexión automática
    reconnect: {
      enabled: true,
      maxAttempts: 10,
      delayMs: 1000,
      maxDelayMs: 30000,
    },
  },

  // === Autenticación ===
  auth: {
    // JWT
    jwt: {
      secret: process.env.JWT_SECRET || 'change-me-in-production',
      expiresIn: '7d',
    },
    // Sesiones
    session: {
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
    },
    // Rate limiting
    rateLimit: {
      login: {
        points: 5,
        duration: 60, // 5 intentos por minuto
      },
      api: {
        points: 100,
        duration: 60, // 100 requests por minuto
      },
    },
  },

  // === Agentes ===
  agents: {
    // Mapeo de agentes permitidos
    // Los usuarios se asignan a agentes específicos
    allowed: ['main', 'ops', 'carlos', 'mia'],
    // Agente por defecto para nuevos usuarios
    default: 'main',
  },

  // === WebSocket ===
  websocket: {
    // Máximo de conexiones por usuario
    maxConnectionsPerUser: 5,
    // Heartbeat interval
    pingInterval: 30000,
    // Timeout de inactividad
    idleTimeout: 300000, // 5 minutos
  },

  // === Uploads ===
  uploads: {
    // Directorio de uploads
    path: './data/uploads',
    // Tamaño máximo
    maxSize: 50 * 1024 * 1024, // 50MB
    // Tipos permitidos
    allowedTypes: [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf',
      'text/plain',
      'audio/mpeg',
      'audio/ogg',
      'video/mp4',
    ],
    // TTL para uploads temporales
    ttl: 3600, // 1 hora
  },

  // === Logging ===
  logging: {
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    // Formato: json para producción, pretty para desarrollo
    format: process.env.NODE_ENV === 'production' ? 'json' : 'pretty',
  },
});
```

---

## Variables de Entorno

### `.env`

```bash
# === Servidor ===
PORT=3000
HOST=0.0.0.0
NODE_ENV=development

# === OpenClaw Gateway ===
OPENCLAW_GATEWAY_URL=ws://localhost:18789
OPENCLAW_GATEWAY_TOKEN=your-gateway-token

# === Autenticación ===
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# === Base de datos ===
DATABASE_PATH=./data/kleoz.db

# === Admin inicial ===
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-immediately

# === Uploads ===
UPLOADS_PATH=./data/uploads
MAX_UPLOAD_SIZE=52428800
```

---

## Configuración de OpenClaw

kleoz necesita que OpenClaw esté configurado correctamente. Aquí está una configuración típica:

### `~/.openclaw/openclaw.json`

```json5
{
  // Gateway
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "your-gateway-token"
    }
  },

  // Agentes
  "agents": {
    "defaults": {
      "model": {
        "primary": "anthropic/claude-opus-4-5"
      },
      "maxConcurrent": 4,
      "contextTokens": 200000
    },
    "list": [
      { "id": "main" },
      { "id": "ops", "name": "Ops Agent" },
      { "id": "carlos", "name": "Carlos Agent" }
    ]
  },

  // Sesiones
  "session": {
    "dmScope": "per-peer",
    "reset": {
      "mode": "daily",
      "atHour": 4
    }
  }
}
```

---

## Esquema de Base de Datos (SQLite)

### Tabla: `users`

```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER,
  settings TEXT -- JSON
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_agent_id ON users(agent_id);
```

### Tabla: `sessions_cache`

```sql
CREATE TABLE sessions_cache (
  session_key TEXT PRIMARY KEY,
  data TEXT NOT NULL, -- JSON
  cached_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_cache_expires ON sessions_cache(expires_at);
```

### Tabla: `ws_connections`

```sql
CREATE TABLE ws_connections (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  connected_at INTEGER NOT NULL,
  last_ping_at INTEGER NOT NULL,
  subscriptions TEXT, -- JSON array de session keys
  
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_ws_connections_user ON ws_connections(user_id);
```

---

## Docker Compose

### `docker-compose.yml`

```yaml
version: '3.8'

services:
  kleoz:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - OPENCLAW_GATEWAY_URL=ws://host.docker.internal:18789
      - OPENCLAW_GATEWAY_TOKEN=${OPENCLAW_GATEWAY_TOKEN}
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_PATH=/data/kleoz.db
    volumes:
      - kleoz-data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  kleoz-data:
```

### `Dockerfile`

```dockerfile
FROM node:22-alpine AS builder

WORKDIR /app

# Instalar dependencias
COPY package*.json ./
COPY packages/api/package*.json ./packages/api/
COPY packages/web/package*.json ./packages/web/
RUN npm ci

# Copiar código
COPY . .

# Build
RUN npm run build

# Production image
FROM node:22-alpine

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

EXPOSE 3000

CMD ["node", "dist/api/index.js"]
```

---

## Configuración de Desarrollo

### Monorepo Setup

```bash
# Instalar dependencias
bun install

# Crear .env (opcional; bun carga .env/.env.local)
cp .env.example .env.local

# La base de datos SQLite se inicializa automáticamente al arrancar el backend.

# Desarrollo (API + Web en paralelo)
bun run dev

# Solo API
bun run --cwd packages/api dev

# Solo Web
bun run --cwd packages/web dev
```

### Scripts de `package.json`

```json
{
  "scripts": {
    "dev": "bunx concurrently \"bun run --cwd packages/api dev\" \"bun run --cwd packages/web dev\"",
    "build": "bun run --cwd packages/api build && bun run --cwd packages/web build",
    "test": "bun run --cwd packages/api test"
  }
}
```

---

## Configuración de TanStack Router

### `packages/web/src/routes/__root.tsx`

```tsx
import { createRootRouteWithContext, Outlet } from '@tanstack/react-router';
import { QueryClient } from '@tanstack/react-query';

interface RouterContext {
  queryClient: QueryClient;
  auth: {
    user: User | null;
    isAuthenticated: boolean;
  };
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootComponent,
});

function RootComponent() {
  return (
    <div className="min-h-screen bg-background">
      <Outlet />
    </div>
  );
}
```

### `packages/web/src/routes/index.tsx`

```tsx
import { createFileRoute, redirect } from '@tanstack/react-router';

export const Route = createFileRoute('/')({
  beforeLoad: ({ context }) => {
    if (!context.auth.isAuthenticated) {
      throw redirect({ to: '/login' });
    }
    throw redirect({ to: '/sessions' });
  },
});
```

---

## Configuración de Zustand

### `packages/web/src/stores/session.ts`

```typescript
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

interface SessionState {
  // Sesiones abiertas (tabs)
  openSessions: string[];
  activeSession: string | null;
  
  // Acciones
  openSession: (key: string) => void;
  closeSession: (key: string) => void;
  setActiveSession: (key: string) => void;
}

export const useSessionStore = create<SessionState>()(
  devtools(
    persist(
      (set) => ({
        openSessions: [],
        activeSession: null,
        
        openSession: (key) =>
          set((state) => ({
            openSessions: state.openSessions.includes(key)
              ? state.openSessions
              : [...state.openSessions, key],
            activeSession: key,
          })),
          
        closeSession: (key) =>
          set((state) => ({
            openSessions: state.openSessions.filter((k) => k !== key),
            activeSession:
              state.activeSession === key
                ? state.openSessions[0] || null
                : state.activeSession,
          })),
          
        setActiveSession: (key) =>
          set({ activeSession: key }),
      }),
      {
        name: 'kleoz-sessions',
      }
    )
  )
);
```

---

## Proxying en Desarrollo

### `packages/web/vite.config.ts`

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { TanStackRouterVite } from '@tanstack/router-plugin/vite';

export default defineConfig({
  plugins: [TanStackRouterVite(), react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
```

---

## Siguiente: [Despliegue](/docs/deployment.md) | [Seguridad](/docs/security.md)
