# API Reference — kleoz

> Documentación completa de la API de kleoz, construida sobre OpenClaw Gateway.

## Introducción

kleoz es una interfaz web multi-agente que se conecta a OpenClaw Gateway. Esta documentación cubre los endpoints y métodos disponibles para integrar tu frontend con el backend.

---

## Arquitectura de Conexión

```
┌─────────────────────────────────────────────────────────────┐
│                     kleoz Frontend                          │
│                                                             │
│  React + TanStack Router + TanStack Query + Zustand         │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ HTTP REST + WebSocket
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                     kleoz API (Hono)                        │
│                                                             │
│  • Auth middleware (JWT)                                    │
│  • Session management                                       │
│  • WebSocket multiplexing                                   │
│  • SQLite (users, cache)                                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ Internal RPC
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  OpenClaw Gateway                           │
│                                                             │
│  Puerto: 18789 (configurable)                               │
│  Protocolo: WebSocket + HTTP                                │
└─────────────────────────────────────────────────────────────┘
```

---

## Autenticación

### POST `/api/auth/login`

Autentica un usuario y devuelve un token JWT.

**Request:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "uuid",
    "username": "string",
    "agentId": "string",
    "role": "user | admin",
    "createdAt": "ISO8601"
  }
}
```

**Errores:**
- `401`: Credenciales inválidas
- `429`: Rate limit excedido

---

### POST `/api/auth/logout`

Invalida el token actual.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "ok": true
}
```

---

### GET `/api/auth/me`

Obtiene información del usuario autenticado.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "id": "uuid",
  "username": "string",
  "agentId": "string",
  "role": "user | admin",
  "permissions": {
    "canSendMessages": true,
    "canViewAllSessions": false,
    "canManageUsers": false
  }
}
```

---

## Sesiones

### GET `/api/sessions`

Lista todas las sesiones del agente autenticado.

**Headers:**
```
Authorization: Bearer <token>
```

**Query params:**
- `limit` (number, opcional): Máximo de sesiones a devolver. Default: 50
- `activeMinutes` (number, opcional): Solo sesiones activas en los últimos N minutos
- `kind` (string, opcional): Filtrar por tipo (`dm`, `group`, `channel`)

**Response (200):**
```json
{
  "count": 15,
  "sessions": [
    {
      "key": "agent:main:dm:tomas",
      "sessionId": "uuid",
      "kind": "dm",
      "channel": "whatsapp",
      "displayName": "+34690395233",
      "updatedAt": 1770700125208,
      "model": "claude-opus-4-5",
      "totalTokens": 21398,
      "contextTokens": 200000,
      "origin": {
        "label": "Tomás",
        "provider": "whatsapp",
        "from": "+34690395233"
      }
    }
  ]
}
```

---

### GET `/api/sessions/:sessionKey`

Obtiene detalles de una sesión específica.

**Response (200):**
```json
{
  "key": "agent:main:dm:tomas",
  "sessionId": "uuid",
  "kind": "dm",
  "channel": "whatsapp",
  "displayName": "Tomás",
  "updatedAt": 1770700125208,
  "model": "claude-opus-4-5",
  "totalTokens": 21398,
  "inputTokens": 15000,
  "outputTokens": 6398,
  "contextTokens": 200000,
  "abortedLastRun": false,
  "transcriptPath": "uuid.jsonl"
}
```

---

### GET `/api/sessions/:sessionKey/history`

Obtiene el historial de mensajes de una sesión.

**Query params:**
- `limit` (number, opcional): Máximo de mensajes. Default: 100
- `includeTools` (boolean, opcional): Incluir llamadas a herramientas. Default: false
- `before` (string, opcional): Cursor para paginación

**Response (200):**
```json
{
  "messages": [
    {
      "id": "msg_uuid",
      "role": "user",
      "content": "Hola, ¿cómo estás?",
      "timestamp": "2026-02-10T05:00:00.000Z",
      "metadata": {
        "channel": "whatsapp",
        "from": "+34690395233"
      }
    },
    {
      "id": "msg_uuid2",
      "role": "assistant",
      "content": "¡Hola! Estoy bien, gracias por preguntar.",
      "timestamp": "2026-02-10T05:00:05.000Z",
      "model": "claude-opus-4-5",
      "tokens": {
        "input": 150,
        "output": 45
      }
    }
  ],
  "hasMore": true,
  "nextCursor": "cursor_token"
}
```

---

### DELETE `/api/sessions/:sessionKey`

Elimina una sesión y su historial.

**Response (200):**
```json
{
  "ok": true,
  "deleted": {
    "sessionKey": "agent:main:dm:test",
    "transcriptDeleted": true
  }
}
```

---

## Mensajes

### POST `/api/messages/send`

Envía un mensaje a una sesión.

**Request:**
```json
{
  "sessionKey": "agent:main:dm:tomas",
  "message": "string",
  "attachments": [
    {
      "type": "image | file | audio",
      "data": "base64...",
      "filename": "image.png",
      "mimeType": "image/png"
    }
  ]
}
```

**Response (200):**
```json
{
  "ok": true,
  "runId": "run_uuid",
  "status": "accepted"
}
```

La respuesta real llega por WebSocket (ver sección WebSocket).

---

### POST `/api/messages/upload`

Sube un archivo para enviar como attachment.

**Request:**
```
Content-Type: multipart/form-data

file: <binary>
```

**Response (200):**
```json
{
  "id": "upload_uuid",
  "filename": "document.pdf",
  "mimeType": "application/pdf",
  "size": 1024000,
  "url": "/api/uploads/upload_uuid",
  "expiresAt": "2026-02-10T06:00:00.000Z"
}
```

---

## WebSocket API

### Conexión

```
ws://localhost:3000/api/ws
```

**Handshake:**
```json
{
  "type": "connect",
  "token": "jwt_token"
}
```

**Response:**
```json
{
  "type": "connected",
  "sessionId": "ws_session_uuid"
}
```

---

### Suscripción a sesiones

```json
{
  "type": "subscribe",
  "sessionKeys": ["agent:main:dm:tomas", "agent:main:group:team"]
}
```

---

### Eventos recibidos

#### Nuevo mensaje (streaming)

```json
{
  "type": "message.delta",
  "sessionKey": "agent:main:dm:tomas",
  "runId": "run_uuid",
  "delta": {
    "content": "fragmento de texto..."
  }
}
```

#### Mensaje completo

```json
{
  "type": "message.complete",
  "sessionKey": "agent:main:dm:tomas",
  "runId": "run_uuid",
  "message": {
    "id": "msg_uuid",
    "role": "assistant",
    "content": "Respuesta completa del agente",
    "timestamp": "ISO8601",
    "tokens": {
      "input": 500,
      "output": 150
    }
  }
}
```

#### Tool call (opcional)

```json
{
  "type": "tool.call",
  "sessionKey": "agent:main:dm:tomas",
  "runId": "run_uuid",
  "tool": {
    "name": "web_search",
    "args": { "query": "..." },
    "status": "running | completed | error"
  }
}
```

#### Estado de sesión

```json
{
  "type": "session.status",
  "sessionKey": "agent:main:dm:tomas",
  "status": "idle | thinking | typing"
}
```

#### Error

```json
{
  "type": "error",
  "sessionKey": "agent:main:dm:tomas",
  "error": {
    "code": "AGENT_TIMEOUT",
    "message": "El agente no respondió a tiempo"
  }
}
```

---

## Agentes (Admin)

### GET `/api/agents`

Lista todos los agentes configurados (solo admin).

**Response (200):**
```json
{
  "agents": [
    {
      "id": "main",
      "name": "Kleo",
      "workspace": "/root/kleo",
      "identity": {
        "name": "Kleo",
        "emoji": "🦁"
      },
      "model": {
        "primary": "anthropic/claude-opus-4-5"
      }
    }
  ]
}
```

---

### GET `/api/agents/:agentId/config`

Obtiene la configuración de un agente.

---

## Usuarios (Admin)

### GET `/api/users`

Lista todos los usuarios.

### POST `/api/users`

Crea un nuevo usuario.

**Request:**
```json
{
  "username": "string",
  "password": "string",
  "agentId": "string",
  "role": "user | admin"
}
```

### PUT `/api/users/:userId`

Actualiza un usuario.

### DELETE `/api/users/:userId`

Elimina un usuario.

---

## Health & Status

### GET `/api/health`

Health check del servidor.

**Response (200):**
```json
{
  "status": "ok",
  "timestamp": "ISO8601",
  "gateway": {
    "connected": true,
    "latency": 5
  },
  "database": {
    "connected": true
  }
}
```

---

### GET `/api/status`

Estado detallado del sistema.

**Response (200):**
```json
{
  "version": "1.0.0",
  "uptime": 3600,
  "gateway": {
    "url": "ws://localhost:18789",
    "connected": true,
    "protocol": 3
  },
  "sessions": {
    "active": 5,
    "total": 150
  },
  "users": {
    "online": 3,
    "total": 10
  }
}
```

---

## Códigos de Error

| Código | Descripción |
|--------|-------------|
| `UNAUTHORIZED` | Token inválido o expirado |
| `FORBIDDEN` | Sin permisos para esta acción |
| `NOT_FOUND` | Recurso no encontrado |
| `AGENT_TIMEOUT` | El agente no respondió a tiempo |
| `GATEWAY_UNAVAILABLE` | OpenClaw Gateway no disponible |
| `RATE_LIMIT` | Demasiadas peticiones |
| `INVALID_REQUEST` | Parámetros inválidos |

---

## Rate Limits

| Endpoint | Límite |
|----------|--------|
| `/api/auth/login` | 5 req/min |
| `/api/messages/send` | 30 req/min |
| `/api/messages/upload` | 10 req/min |
| WebSocket messages | 60 msg/min |

---

## Ejemplos

### cURL: Login

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}'
```

### cURL: Listar sesiones

```bash
curl http://localhost:3000/api/sessions \
  -H "Authorization: Bearer eyJhbGciOi..."
```

### cURL: Enviar mensaje

```bash
curl -X POST http://localhost:3000/api/messages/send \
  -H "Authorization: Bearer eyJhbGciOi..." \
  -H "Content-Type: application/json" \
  -d '{
    "sessionKey": "agent:main:dm:tomas",
    "message": "¿Cuál es el clima hoy?"
  }'
```

### JavaScript: WebSocket

```javascript
const ws = new WebSocket('ws://localhost:3000/api/ws');

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'connect',
    token: 'jwt_token'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch (data.type) {
    case 'connected':
      // Suscribirse a sesiones
      ws.send(JSON.stringify({
        type: 'subscribe',
        sessionKeys: ['agent:main:dm:tomas']
      }));
      break;
      
    case 'message.delta':
      // Actualizar UI con streaming
      appendToMessage(data.delta.content);
      break;
      
    case 'message.complete':
      // Mensaje final
      finalizeMessage(data.message);
      break;
  }
};
```

---

## Siguiente: [Sesiones](/docs/sessions.md) | [Autenticación](/docs/auth.md)
