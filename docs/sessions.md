# Sesiones — kleoz

> Guía completa de gestión de sesiones en kleoz, basada en OpenClaw Gateway.

## Conceptos Fundamentales

### ¿Qué es una sesión?

Una **sesión** en kleoz representa una conversación entre un usuario y un agente. Cada sesión tiene:

- **Session Key**: Identificador único (ej: `agent:main:dm:tomas`)
- **Session ID**: UUID interno
- **Historial**: Mensajes almacenados en formato JSONL
- **Contexto**: Tokens acumulados para el modelo
- **Metadata**: Canal, origen, timestamps, etc.

---

## Tipos de Sesiones

### DM (Mensajes Directos)

Conversaciones 1:1 entre un usuario y el agente.

```
Session Key: agent:<agentId>:<mainKey>
            agent:<agentId>:dm:<peerId>
            agent:<agentId>:<channel>:dm:<peerId>
```

**Modos de scope (`dmScope`):**

| Modo | Descripción | Session Key |
|------|-------------|-------------|
| `main` | Todos los DMs comparten sesión | `agent:main:main` |
| `per-peer` | Aislado por usuario | `agent:main:dm:tomas` |
| `per-channel-peer` | Aislado por canal + usuario | `agent:main:whatsapp:dm:+34690395233` |
| `per-account-channel-peer` | Aislado por cuenta + canal + usuario | `agent:main:whatsapp:default:dm:+34690395233` |

---

### Grupos

Conversaciones grupales donde el agente participa.

```
Session Key: agent:<agentId>:<channel>:group:<groupId>
```

**Ejemplos:**
- WhatsApp: `agent:main:whatsapp:group:120363424660241481@g.us`
- Telegram: `agent:main:telegram:group:-1001234567890`
- Discord: `agent:main:discord:channel:1234567890`

---

### Threads (Hilos)

Hilos dentro de canales (Slack, Discord, Telegram topics).

```
Session Key: agent:<agentId>:<channel>:group:<groupId>:topic:<threadId>
```

---

## Ciclo de Vida

### Creación

Las sesiones se crean automáticamente cuando:
1. Un usuario envía el primer mensaje
2. kleoz recibe un mensaje desde un canal externo
3. Se inicia una conversación vía API

### Reset

Las sesiones se reinician según la política configurada:

```typescript
// Configuración de reset
{
  session: {
    reset: {
      mode: "daily",      // daily | idle
      atHour: 4,          // Reset a las 4:00 AM
      idleMinutes: 120    // O después de 2h de inactividad
    },
    resetByType: {
      direct: { mode: "idle", idleMinutes: 240 },
      group: { mode: "idle", idleMinutes: 120 },
      thread: { mode: "daily", atHour: 4 }
    }
  }
}
```

**Triggers manuales:**
- `/new` — Inicia una nueva sesión
- `/reset` — Reinicia la sesión actual
- `/new opus` — Nueva sesión con modelo específico

### Compactación

Cuando el contexto crece demasiado, OpenClaw compacta automáticamente:

1. Resume mensajes antiguos
2. Mantiene los últimos N mensajes intactos
3. Preserva información crítica (decisiones, tareas)

```typescript
// Configuración de compactación
{
  agents: {
    defaults: {
      compaction: {
        mode: "safeguard",
        reserveTokensFloor: 20000,
        memoryFlush: {
          enabled: true,
          softThresholdTokens: 4000
        }
      }
    }
  }
}
```

---

## API de Sesiones (kleoz)

### Listar Sesiones

```http
GET /api/sessions?limit=50&activeMinutes=60
Authorization: Bearer <token>
```

**Response:**
```json
{
  "count": 12,
  "sessions": [
    {
      "key": "agent:main:dm:tomas",
      "sessionId": "a1b2c3d4-...",
      "kind": "dm",
      "channel": "whatsapp",
      "displayName": "Tomás",
      "updatedAt": 1770700125208,
      "model": "claude-opus-4-5",
      "totalTokens": 21398,
      "contextTokens": 200000,
      "status": "idle"
    }
  ]
}
```

---

### Obtener Sesión

```http
GET /api/sessions/:sessionKey
Authorization: Bearer <token>
```

**URL Encoding:**
El sessionKey debe estar URL-encoded:
```
/api/sessions/agent%3Amain%3Adm%3Atomas
```

---

### Historial de Mensajes

```http
GET /api/sessions/:sessionKey/history?limit=100&includeTools=false
Authorization: Bearer <token>
```

**Response:**
```json
{
  "messages": [
    {
      "id": "msg_001",
      "role": "user",
      "content": "¿Puedes buscar información sobre React?",
      "timestamp": "2026-02-10T10:00:00.000Z",
      "metadata": {
        "from": "+34690395233",
        "channel": "whatsapp"
      }
    },
    {
      "id": "msg_002",
      "role": "assistant",
      "content": "Claro, voy a buscar información actualizada sobre React...",
      "timestamp": "2026-02-10T10:00:05.000Z",
      "model": "claude-opus-4-5",
      "tokens": { "input": 250, "output": 180 },
      "tools": [
        {
          "name": "web_search",
          "args": { "query": "React framework 2026" },
          "result": "..."
        }
      ]
    }
  ],
  "hasMore": true,
  "nextCursor": "cursor_abc123"
}
```

---

### Eliminar Sesión

```http
DELETE /api/sessions/:sessionKey
Authorization: Bearer <token>
```

**Response:**
```json
{
  "ok": true,
  "deleted": {
    "sessionKey": "agent:main:dm:test",
    "messagesDeleted": 45,
    "transcriptDeleted": true
  }
}
```

---

## WebSocket: Suscripción a Sesiones

### Suscribirse

```json
{
  "type": "subscribe",
  "sessionKeys": [
    "agent:main:dm:tomas",
    "agent:main:group:team"
  ]
}
```

### Desuscribirse

```json
{
  "type": "unsubscribe",
  "sessionKeys": ["agent:main:dm:tomas"]
}
```

### Eventos de Sesión

```json
// Sesión actualizada
{
  "type": "session.updated",
  "sessionKey": "agent:main:dm:tomas",
  "changes": {
    "totalTokens": 22500,
    "updatedAt": 1770700200000
  }
}

// Nueva sesión creada
{
  "type": "session.created",
  "session": { ... }
}

// Sesión eliminada
{
  "type": "session.deleted",
  "sessionKey": "agent:main:dm:old"
}
```

---

## Filtros y Permisos

### Por Agente

Cada usuario de kleoz está asociado a uno o más agentes:

```typescript
// Usuario solo ve sesiones de su agente
const user = {
  id: "user_123",
  agentId: "main",
  role: "user"
};

// Filtrado automático en queries
GET /api/sessions
// → Solo devuelve sesiones donde key.startsWith(`agent:${user.agentId}`)
```

### Admin Override

Los admins pueden ver todas las sesiones:

```typescript
const admin = {
  id: "admin_001",
  role: "admin",
  permissions: {
    canViewAllSessions: true
  }
};

// Query con filtro explícito
GET /api/sessions?agentId=ops
```

---

## Sincronización con OpenClaw

### Flujo de Datos

```
┌─────────────────┐
│  kleoz Frontend │
└────────┬────────┘
         │ WebSocket
         ▼
┌─────────────────┐     ┌─────────────────┐
│   kleoz API     │────▶│    SQLite       │
│   (Hono)        │     │  (cache local)  │
└────────┬────────┘     └─────────────────┘
         │
         │ Internal RPC
         ▼
┌─────────────────┐     ┌─────────────────┐
│ OpenClaw Gateway│────▶│  JSONL Files    │
│   (source of    │     │ (source of      │
│    truth)       │     │  truth)         │
└─────────────────┘     └─────────────────┘
```

### Estrategia de Cache

1. **Sesiones**: Cache en SQLite, TTL 60s
2. **Historial**: Cache en memoria, invalidado por eventos WS
3. **Tokens/Counts**: Actualizados en tiempo real via WS

### Invalidación

```typescript
// Cuando llega un evento de OpenClaw
gateway.on('session.updated', (event) => {
  // Invalidar cache local
  cache.delete(`session:${event.sessionKey}`);
  
  // Notificar a clientes suscritos
  broadcast({
    type: 'session.updated',
    sessionKey: event.sessionKey,
    changes: event.changes
  });
});
```

---

## Límites y Cuotas

### Límites por Defecto

| Recurso | Límite |
|---------|--------|
| Sesiones activas por agente | Sin límite |
| Mensajes por sesión | Sin límite |
| Historial cargable | 1000 mensajes/request |
| WebSocket suscripciones | 50 sesiones/conexión |

### Context Window

| Modelo | Context Tokens |
|--------|----------------|
| claude-opus-4-5 | 200,000 |
| claude-sonnet-4-5 | 200,000 |
| gpt-5.2 | 128,000 |

---

## Ejemplos de Integración

### React Hook: useSessions

```typescript
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useWebSocket } from './useWebSocket';

export function useSessions() {
  const queryClient = useQueryClient();
  const ws = useWebSocket();

  // Query inicial
  const query = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get('/sessions'),
    staleTime: 60_000
  });

  // Escuchar actualizaciones WS
  useEffect(() => {
    ws.on('session.updated', (event) => {
      queryClient.setQueryData(['sessions'], (old) => ({
        ...old,
        sessions: old.sessions.map(s =>
          s.key === event.sessionKey
            ? { ...s, ...event.changes }
            : s
        )
      }));
    });
  }, [ws, queryClient]);

  return query;
}
```

### React Hook: useSessionHistory

```typescript
export function useSessionHistory(sessionKey: string) {
  const ws = useWebSocket();
  const [messages, setMessages] = useState<Message[]>([]);

  // Cargar historial inicial
  const query = useQuery({
    queryKey: ['history', sessionKey],
    queryFn: () => api.get(`/sessions/${encodeURIComponent(sessionKey)}/history`)
  });

  // Escuchar mensajes nuevos
  useEffect(() => {
    ws.subscribe([sessionKey]);

    ws.on('message.complete', (event) => {
      if (event.sessionKey === sessionKey) {
        setMessages(prev => [...prev, event.message]);
      }
    });

    return () => ws.unsubscribe([sessionKey]);
  }, [sessionKey, ws]);

  return {
    ...query,
    messages: [...(query.data?.messages || []), ...messages]
  };
}
```

---

## Siguiente: [Mensajes](/docs/messages.md) | [WebSocket](/docs/websocket.md)
