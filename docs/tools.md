# Herramientas (Tools) — kleoz

> Referencia completa de las herramientas disponibles para los agentes en kleoz/OpenClaw.

## Introducción

Los agentes de OpenClaw tienen acceso a un conjunto de herramientas que les permiten interactuar con el sistema, ejecutar código, navegar la web, y más. kleoz expone estas capacidades a través de su interfaz.

---

## Herramientas Core

### `exec`

Ejecuta comandos de shell en el workspace.

```typescript
interface ExecParams {
  command: string;           // Comando a ejecutar
  workdir?: string;          // Directorio de trabajo
  timeout?: number;          // Timeout en segundos (default: 1800)
  yieldMs?: number;          // Auto-background después de N ms
  background?: boolean;      // Ejecutar en background inmediatamente
  pty?: boolean;             // Usar pseudo-terminal (para CLIs interactivas)
  env?: Record<string, string>; // Variables de entorno
}
```

**Ejemplo de uso en chat:**
```
Usuario: Ejecuta `ls -la` en el directorio actual
Agente: [Ejecutando exec...]
```

---

### `read`

Lee contenido de archivos.

```typescript
interface ReadParams {
  path: string;              // Ruta del archivo
  offset?: number;           // Línea inicial (1-indexed)
  limit?: number;            // Máximo de líneas
}
```

**Soporta:**
- Archivos de texto (truncados a 2000 líneas o 50KB)
- Imágenes (jpg, png, gif, webp) — enviadas como attachments

---

### `write`

Escribe contenido a un archivo.

```typescript
interface WriteParams {
  path: string;              // Ruta del archivo
  content: string;           // Contenido a escribir
}
```

Crea directorios padre automáticamente.

---

### `edit`

Edita archivos reemplazando texto exacto.

```typescript
interface EditParams {
  path: string;              // Ruta del archivo
  oldText: string;           // Texto exacto a buscar
  newText: string;           // Texto de reemplazo
}
```

---

### `process`

Gestiona sesiones de ejecución en background.

```typescript
interface ProcessParams {
  action: 'list' | 'poll' | 'log' | 'write' | 'send-keys' | 'kill';
  sessionId?: string;        // ID de la sesión
  data?: string;             // Datos para write
  keys?: string[];           // Teclas para send-keys
  limit?: number;            // Límite de log
  offset?: number;           // Offset de log
}
```

---

## Herramientas Web

### `web_search`

Busca en la web usando Brave Search API.

```typescript
interface WebSearchParams {
  query: string;             // Consulta de búsqueda
  count?: number;            // Resultados (1-10)
  country?: string;          // Código de país (ej: 'ES', 'US')
  search_lang?: string;      // Idioma de resultados
  freshness?: string;        // Filtro temporal: 'pd', 'pw', 'pm', 'py'
}
```

---

### `web_fetch`

Extrae contenido legible de una URL.

```typescript
interface WebFetchParams {
  url: string;               // URL a obtener
  extractMode?: 'markdown' | 'text';
  maxChars?: number;         // Máximo de caracteres
}
```

---

## Herramientas de Browser

### `browser`

Control del navegador web.

```typescript
interface BrowserParams {
  action: 'status' | 'start' | 'stop' | 'open' | 'snapshot' | 
          'screenshot' | 'navigate' | 'act';
  profile?: string;          // Perfil del navegador
  targetUrl?: string;        // URL a abrir
  ref?: string;              // Referencia de elemento
  request?: BrowserRequest;  // Acción a realizar
}

interface BrowserRequest {
  kind: 'click' | 'type' | 'press' | 'hover' | 'select' | 'wait';
  ref?: string;              // Referencia del elemento
  text?: string;             // Texto a escribir
  key?: string;              // Tecla a presionar
}
```

**Ejemplo:**
```
Agente: [browser: snapshot del perfil "openclaw"]
→ Devuelve árbol de accesibilidad de la página actual

Agente: [browser: act click en ref="button-submit"]
→ Hace click en el botón
```

---

## Herramientas de Canvas

### `canvas`

Control de canvas para presentaciones visuales.

```typescript
interface CanvasParams {
  action: 'present' | 'hide' | 'navigate' | 'eval' | 'snapshot';
  url?: string;              // URL a navegar
  javaScript?: string;       // JS a ejecutar
  width?: number;
  height?: number;
}
```

---

## Herramientas de Nodos

### `nodes`

Interacción con dispositivos conectados (iOS, Android, etc.).

```typescript
interface NodesParams {
  action: 'status' | 'describe' | 'notify' | 'camera_snap' | 
          'screen_record' | 'location_get' | 'run';
  node?: string;             // ID o nombre del nodo
  command?: string[];        // Comando a ejecutar
  body?: string;             // Cuerpo de notificación
  title?: string;            // Título de notificación
  facing?: 'front' | 'back'; // Cámara a usar
  durationMs?: number;       // Duración de grabación
}
```

---

## Herramientas de Automatización

### `cron`

Gestión de tareas programadas.

```typescript
interface CronParams {
  action: 'status' | 'list' | 'add' | 'update' | 'remove' | 'run' | 'runs';
  jobId?: string;
  job?: CronJob;
  patch?: Partial<CronJob>;
}

interface CronJob {
  name?: string;
  schedule: CronSchedule;
  payload: CronPayload;
  sessionTarget: 'main' | 'isolated';
  enabled?: boolean;
}
```

---

### `gateway`

Control del gateway de OpenClaw.

```typescript
interface GatewayParams {
  action: 'restart' | 'config.get' | 'config.apply' | 'update.run';
  raw?: string;              // Config raw para apply
}
```

---

## Herramientas de Sesiones

### `sessions_list`

Lista sesiones activas.

```typescript
interface SessionsListParams {
  limit?: number;
  activeMinutes?: number;
  kinds?: string[];
  messageLimit?: number;
}
```

---

### `sessions_history`

Obtiene historial de una sesión.

```typescript
interface SessionsHistoryParams {
  sessionKey: string;
  limit?: number;
  includeTools?: boolean;
}
```

---

### `sessions_send`

Envía mensaje a otra sesión.

```typescript
interface SessionsSendParams {
  sessionKey?: string;
  label?: string;
  message: string;
  timeoutSeconds?: number;
}
```

---

### `sessions_spawn`

Crea un sub-agente en sesión aislada.

```typescript
interface SessionsSpawnParams {
  task: string;              // Tarea a ejecutar
  agentId?: string;          // Agente a usar
  model?: string;            // Modelo a usar
  label?: string;            // Etiqueta de la sesión
  runTimeoutSeconds?: number;
  cleanup?: 'delete' | 'keep';
}
```

---

### `session_status`

Muestra estado de la sesión actual.

```typescript
interface SessionStatusParams {
  sessionKey?: string;
  model?: string;            // Override de modelo
}
```

---

## Herramientas de Mensajería

### `message`

Envía mensajes a canales externos.

```typescript
interface MessageParams {
  action: 'send' | 'broadcast' | 'react' | 'poll';
  channel?: string;          // telegram, whatsapp, discord, etc.
  target?: string;           // Destinatario
  message?: string;          // Contenido
  media?: string;            // Path de media
  emoji?: string;            // Para reacciones
  pollQuestion?: string;     // Para encuestas
  pollOption?: string[];     // Opciones de encuesta
}
```

---

## Herramientas de Media

### `image`

Analiza imágenes con modelos de visión.

```typescript
interface ImageParams {
  image: string;             // Path o URL
  prompt?: string;           // Prompt de análisis
  model?: string;            // Modelo a usar
}
```

---

### `tts`

Convierte texto a voz.

```typescript
interface TTSParams {
  text: string;              // Texto a convertir
  channel?: string;          // Canal para formato de salida
}
```

---

## Políticas de Herramientas

### Perfiles

```typescript
// tools.profile define un conjunto base
{
  "tools": {
    "profile": "coding"  // minimal | coding | messaging | full
  }
}
```

| Perfil | Herramientas incluidas |
|--------|------------------------|
| `minimal` | session_status |
| `coding` | group:fs, group:runtime, group:sessions, image |
| `messaging` | group:messaging, sessions_list, sessions_history, sessions_send, session_status |
| `full` | Sin restricción |

---

### Grupos

```typescript
// Grupos de herramientas para allow/deny
{
  "tools": {
    "allow": ["group:fs", "browser"]
  }
}
```

| Grupo | Herramientas |
|-------|--------------|
| `group:runtime` | exec, bash, process |
| `group:fs` | read, write, edit, apply_patch |
| `group:sessions` | sessions_list, sessions_history, sessions_send, sessions_spawn, session_status |
| `group:web` | web_search, web_fetch |
| `group:ui` | browser, canvas |
| `group:automation` | cron, gateway |
| `group:messaging` | message |
| `group:nodes` | nodes |

---

### Allow/Deny

```typescript
{
  "tools": {
    "allow": ["group:fs", "web_search"],
    "deny": ["exec"]  // deny siempre gana
  }
}
```

---

## Visualización en kleoz

### Indicadores de Tool Calls

En la interfaz de kleoz, las llamadas a herramientas se muestran como:

```
┌─────────────────────────────────────┐
│ 🔧 exec                             │
│ ┌─────────────────────────────────┐ │
│ │ $ ls -la                        │ │
│ └─────────────────────────────────┘ │
│                                     │
│ ✓ Completado (0.5s)                │
│ ┌─────────────────────────────────┐ │
│ │ total 24                        │ │
│ │ drwxr-xr-x  5 root root 4096... │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### Estados de Tool Calls

| Estado | Icono | Descripción |
|--------|-------|-------------|
| `running` | ⏳ | Ejecutando |
| `completed` | ✓ | Completado exitosamente |
| `error` | ✗ | Error |
| `cancelled` | ⊘ | Cancelado |

---

## Eventos WebSocket

Las tool calls se transmiten en tiempo real:

```json
{
  "type": "tool.call",
  "sessionKey": "agent:main:dm:tomas",
  "runId": "run_uuid",
  "tool": {
    "id": "call_123",
    "name": "exec",
    "args": { "command": "ls -la" },
    "status": "running"
  }
}
```

```json
{
  "type": "tool.result",
  "sessionKey": "agent:main:dm:tomas",
  "runId": "run_uuid",
  "tool": {
    "id": "call_123",
    "name": "exec",
    "status": "completed",
    "result": "total 24\ndrwxr-xr-x..."
  }
}
```

---

## Siguiente: [WebSocket](/docs/websocket.md) | [Seguridad](/docs/security.md)
