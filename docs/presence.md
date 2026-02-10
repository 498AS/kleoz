# Presence — kleoz

> Sistema de presencia en tiempo real para usuarios y dispositivos conectados.

## Introducción

El sistema de **presence** proporciona visibilidad en tiempo real de:
- Usuarios conectados a cada agente
- Dispositivos y clientes activos
- Estado de las conexiones (activo/idle/stale)

Está construido sobre el sistema de presence de OpenClaw Gateway.

---

## Estructura de Datos

### PresenceEntry

```typescript
interface PresenceEntry {
  // Identificación
  instanceId: string;        // ID estable del cliente (crucial para dedup)
  host: string;              // Nombre del host
  ip: string;                // Dirección IP

  // Información del cliente
  version: string;           // Versión del cliente
  platform?: string;         // "macos" | "ios" | "android" | "linux" | "windows"
  deviceFamily?: string;     // "iPhone" | "Mac" | "iPad" | etc.
  modelIdentifier?: string;  // "iPhone15,2" | "MacBookPro18,1" | etc.

  // Estado
  mode: PresenceMode;        // Tipo de cliente
  roles?: string[];          // ["operator", "node"]
  scopes?: string[];         // ["operator.read", "operator.write"]

  // Actividad
  lastInputSeconds?: number; // Segundos desde última interacción
  reason: PresenceReason;    // Origen de la entrada
  ts: number;                // Timestamp (ms since epoch)
}

type PresenceMode = 
  | 'ui'        // macOS/iOS app
  | 'webchat'   // Web chat interface
  | 'cli'       // Command line
  | 'node'      // Node device (camera, canvas, etc.)
  | 'backend'   // Server/automation
  | 'probe'     // Health check
  | 'test';     // Testing

type PresenceReason =
  | 'self'           // Gateway self-entry
  | 'connect'        // WS connection established
  | 'node-connected' // Node joined
  | 'periodic';      // Heartbeat beacon
```

---

## Productores de Presence

```
┌─────────────────────────────────────────────────────────────┐
│                    OPENCLAW GATEWAY                         │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 1. Self Entry                                           ││
│  │    → Siempre presente al arrancar el gateway            ││
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 2. WebSocket Connect                                    ││
│  │    → Cada cliente que conecta genera una entrada        ││
│  │    → CLI one-off NO genera entrada (evita spam)         ││
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 3. System-Event Beacons                                 ││
│  │    → Heartbeats periódicos con info actualizada         ││
│  │    → Host, IP, lastInputSeconds                         ││
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 4. Node Connects                                        ││
│  │    → Dispositivos iOS/Android/etc.                      ││
│  │    → Incluye capabilities (camera, canvas, etc.)        ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Integración en kleoz

### API Endpoints

#### GET `/api/presence`

Obtiene el estado actual de presence.

```typescript
// Response
{
  entries: PresenceEntry[];
  gatewayUptime: number;
  timestamp: number;
}
```

#### WebSocket Events

```typescript
// Suscribirse a presence
ws.send({ type: 'subscribe.presence' });

// Evento de actualización
{
  type: 'presence.updated',
  entries: PresenceEntry[],
  stateVersion: number
}

// Evento de nueva conexión
{
  type: 'presence.joined',
  entry: PresenceEntry
}

// Evento de desconexión
{
  type: 'presence.left',
  instanceId: string
}
```

---

## Estados de Usuario

kleoz deriva estados de UI a partir de los datos de presence:

```typescript
type UserStatus = 'active' | 'idle' | 'away' | 'offline';

function getUserStatus(entry: PresenceEntry): UserStatus {
  const age = Date.now() - entry.ts;
  
  // Offline: más de 5 minutos sin actualización
  if (age > 5 * 60 * 1000) return 'offline';
  
  // Away: más de 2 minutos sin input
  if (entry.lastInputSeconds && entry.lastInputSeconds > 120) {
    return 'away';
  }
  
  // Idle: más de 30 segundos sin input
  if (entry.lastInputSeconds && entry.lastInputSeconds > 30) {
    return 'idle';
  }
  
  return 'active';
}
```

---

## Visualización en UI

### Lista de Usuarios Conectados

```tsx
function PresenceList() {
  const { entries } = usePresence();
  
  return (
    <div className="presence-list">
      {entries.map(entry => (
        <PresenceItem key={entry.instanceId} entry={entry} />
      ))}
    </div>
  );
}

function PresenceItem({ entry }: { entry: PresenceEntry }) {
  const status = getUserStatus(entry);
  
  return (
    <div className="presence-item">
      <StatusIndicator status={status} />
      <span className="host">{entry.host}</span>
      <span className="device">{entry.deviceFamily}</span>
      <span className="mode">{entry.mode}</span>
    </div>
  );
}
```

### Indicadores de Estado

| Estado | Color | Descripción |
|--------|-------|-------------|
| Active | 🟢 Verde | Interactuando activamente |
| Idle | 🟡 Amarillo | Conectado pero inactivo |
| Away | 🟠 Naranja | Sin actividad prolongada |
| Offline | ⚫ Gris | Desconectado |

---

## Deduplicación

### El problema

Sin un `instanceId` estable, un cliente que reconecta puede aparecer como duplicado.

### La solución

```typescript
// El cliente debe enviar un instanceId estable
ws.send({
  type: 'connect',
  params: {
    client: {
      id: 'kleoz-web',
      instanceId: getOrCreateInstanceId(), // Persistido en localStorage
      version: '1.0.0',
      platform: 'web',
      mode: 'webchat'
    }
  }
});

function getOrCreateInstanceId(): string {
  let id = localStorage.getItem('kleoz-instance-id');
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem('kleoz-instance-id', id);
  }
  return id;
}
```

---

## TTL y Límites

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| TTL | 5 minutos | Entradas más antiguas se purgan |
| Max entries | 200 | Límite de entradas en memoria |
| Beacon interval | 30 segundos | Frecuencia de heartbeats |

---

## Casos de Uso

### 1. Mostrar usuarios online por agente

```typescript
function useAgentPresence(agentId: string) {
  const { entries } = usePresence();
  
  return entries.filter(e => 
    e.mode === 'webchat' && 
    e.agentId === agentId
  );
}
```

### 2. Notificar cuando alguien se une

```typescript
useEffect(() => {
  ws.on('presence.joined', (event) => {
    toast(`${event.entry.host} se ha conectado`);
  });
}, []);
```

### 3. Mostrar "escribiendo..." de otros usuarios

```typescript
// Combinar presence con eventos de typing
function useTypingUsers(sessionKey: string) {
  const { entries } = usePresence();
  const [typing, setTyping] = useState<string[]>([]);
  
  useEffect(() => {
    ws.on('session.typing', (event) => {
      if (event.sessionKey === sessionKey) {
        setTyping(event.userIds);
      }
    });
  }, [sessionKey]);
  
  return entries.filter(e => typing.includes(e.instanceId));
}
```

---

## Siguiente: [Security](security.md) | [API Reference](api-reference.md)
