# Contracts Backend <-> Frontend (Source of Truth)

Este documento define los **contratos estables** entre `@kleoz/web` (frontend) y `@kleoz/api` (backend).

Si backend y frontend difieren, **esto manda**: el objetivo es implementar todo lo descrito aqui.

## Convenciones

- Base URL: mismo origen. Frontend llama a rutas relativas (`/api/...`).
- Auth: `Authorization: Bearer <jwt>`.
- `sessionKey` en path: siempre **URL-encoded**.
- Timestamps:
  - `updatedAt`, `createdAt` de sesiones: `number` (ms since epoch).
  - `timestamp` de mensajes: `string` ISO8601.
- Errores: siempre se responde como:

```json
{
  "error": { "code": "FORBIDDEN", "message": "..." }
}
```

## Error Codes

- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `INVALID_REQUEST`
- `RATE_LIMIT`
- `GATEWAY_UNAVAILABLE`
- `AGENT_TIMEOUT`

## REST API

### POST `/api/auth/login`

Request:
```json
{ "username": "string", "password": "string" }
```

Response 200:
```json
{
  "token": "string",
  "expiresAt": "ISO8601",
  "user": { "id": "string", "username": "string", "agentId": "string", "role": "admin|user", "createdAt": "ISO8601" }
}
```

### POST `/api/auth/logout`

Headers: `Authorization: Bearer <jwt>`

Response 200:
```json
{ "ok": true }
```

### GET `/api/auth/me`

Headers: `Authorization: Bearer <jwt>`

Response 200:
```json
{
  "id": "string",
  "username": "string",
  "agentId": "string",
  "role": "admin|user",
  "permissions": {
    "canSendMessages": true,
    "canViewAllSessions": false,
    "canManageUsers": false
  }
}
```

### GET `/api/sessions`

Headers: `Authorization: Bearer <jwt>`

Query:
- `limit?: number` default 50
- `activeMinutes?: number`
- `kind?: "dm"|"group"|"channel"`

Response 200:
```json
{ "count": 0, "sessions": [ { "key": "string", "sessionId": "string", "kind": "dm", "channel": "string", "displayName": "string", "updatedAt": 0, "model": "string", "totalTokens": 0, "contextTokens": 0 } ] }
```

### GET `/api/sessions/:sessionKey`

Headers: `Authorization: Bearer <jwt>`

Response 200:
```json
{ "key": "string", "sessionId": "string", "kind": "dm", "channel": "string", "displayName": "string", "updatedAt": 0, "model": "string", "totalTokens": 0, "inputTokens": 0, "outputTokens": 0, "contextTokens": 0, "abortedLastRun": false, "transcriptPath": "string" }
```

### GET `/api/sessions/:sessionKey/history`

Headers: `Authorization: Bearer <jwt>`

Query:
- `limit?: number` default 100
- `includeTools?: boolean` default false
- `before?: string` (cursor)

Response 200:
```json
{
  "messages": [
    {
      "id": "string",
      "role": "user|assistant|tool",
      "content": "string",
      "timestamp": "ISO8601",
      "model": "string",
      "tokens": { "input": 0, "output": 0 },
      "metadata": {}
    }
  ],
  "hasMore": false,
  "nextCursor": "string"
}
```

### DELETE `/api/sessions/:sessionKey`

Headers: `Authorization: Bearer <jwt>`

Response 200:
```json
{ "ok": true, "deleted": { "sessionKey": "string", "transcriptDeleted": true } }
```

### POST `/api/messages/send`

Headers: `Authorization: Bearer <jwt>`

Request:
```json
{
  "sessionKey": "string",
  "message": "string",
  "attachments": [
    { "type": "image|file|audio", "data": "base64...", "filename": "string", "mimeType": "string" }
  ]
}
```

Response 200:
```json
{ "ok": true, "runId": "string", "status": "accepted" }
```

### POST `/api/messages/upload`

Request: `multipart/form-data` con `file`.

Response 200:
```json
{ "id": "string", "filename": "string", "mimeType": "string", "size": 0, "url": "/api/uploads/string", "expiresAt": "ISO8601" }
```

### GET `/api/uploads/:uploadId`

Devuelve el binario (y headers `Content-Type`/`Content-Length`).

### GET `/api/presence`

Headers: `Authorization: Bearer <jwt>`

Response 200:
```json
{ "entries": [], "gatewayUptime": 0, "timestamp": 0 }
```

### Admin

- GET `/api/agents`
- GET `/api/agents/:agentId/config`
- GET `/api/users`
- POST `/api/users`
- PUT `/api/users/:userId`
- DELETE `/api/users/:userId`

### Health/Status

- GET `/api/health`
- GET `/api/status`

## WebSocket API (`/api/ws`)

### Conexión

El cliente conecta a:
- `ws(s)://<host>/api/ws?token=<jwt>` (recomendado)

Opcionalmente, el primer mensaje puede ser:
```json
{ "type": "connect", "token": "jwt", "client": { "id": "kleoz-web", "instanceId": "uuid", "version": "string", "platform": "web", "mode": "webchat" } }
```

Respuesta:
```json
{ "type": "connected", "wsSessionId": "string" }
```

### Mensajes cliente -> servidor

- Subscribe sesiones:
```json
{ "type": "subscribe", "sessionKeys": ["..."] }
```
- Unsubscribe:
```json
{ "type": "unsubscribe", "sessionKeys": ["..."] }
```
- Subscribe presence:
```json
{ "type": "subscribe.presence" }
```

### Eventos servidor -> cliente

- `message.delta`, `message.complete`
- `tool.call`, `tool.result`
- `session.created`, `session.updated`, `session.deleted`, `session.status`
- `presence.snapshot`, `presence.updated`, `presence.joined`, `presence.left`
- `error`

