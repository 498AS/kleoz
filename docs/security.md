# Security — kleoz

> Guía de seguridad, autenticación y control de acceso.

## Modelo de Autenticación

kleoz implementa un sistema de autenticación en dos capas:

```
┌─────────────────────────────────────────────────────────────┐
│                      CAPA 1: kleoz                          │
│                                                             │
│  Usuario + Contraseña → JWT Token                           │
│  • Usuarios almacenados en SQLite                           │
│  • Passwords hasheados con bcrypt                           │
│  • Tokens JWT con expiración configurable                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    CAPA 2: OpenClaw                         │
│                                                             │
│  Gateway Token (server-to-server)                           │
│  • Token compartido entre kleoz API y Gateway               │
│  • Configurado via OPENCLAW_GATEWAY_TOKEN                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Autenticación de Usuarios

### Registro de Usuario (Admin)

```typescript
// Solo admins pueden crear usuarios
POST /api/users
Authorization: Bearer <admin-token>

{
  "username": "carlos",
  "password": "secure-password-123",
  "agentId": "carlos",
  "role": "user"
}
```

### Login

```typescript
POST /api/auth/login

{
  "username": "carlos",
  "password": "secure-password-123"
}

// Response
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "user_uuid",
    "username": "carlos",
    "agentId": "carlos",
    "role": "user"
  },
  "expiresAt": "2026-02-17T05:00:00.000Z"
}
```

### Token JWT

```typescript
// Payload del token
{
  "sub": "user_uuid",
  "username": "carlos",
  "agentId": "carlos",
  "role": "user",
  "iat": 1707541200,
  "exp": 1708146000
}

// Uso en requests
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

---

## Roles y Permisos

### Roles

| Rol | Descripción |
|-----|-------------|
| `admin` | Acceso total. Puede gestionar usuarios y ver todas las sesiones. |
| `user` | Acceso limitado a su agente asignado. |

### Permisos Detallados

```typescript
interface UserPermissions {
  // Sesiones
  canViewOwnSessions: boolean;    // Ver sesiones de su agente
  canViewAllSessions: boolean;    // Ver sesiones de cualquier agente
  canSendMessages: boolean;       // Enviar mensajes
  canDeleteSessions: boolean;     // Eliminar sesiones
  
  // Usuarios (solo admin)
  canManageUsers: boolean;        // CRUD de usuarios
  canViewAuditLog: boolean;       // Ver logs de auditoría
  
  // Sistema (solo admin)
  canViewSystemStatus: boolean;   // Ver health/status
  canManageConfig: boolean;       // Modificar configuración
}

// Permisos por rol
const ROLE_PERMISSIONS = {
  admin: {
    canViewOwnSessions: true,
    canViewAllSessions: true,
    canSendMessages: true,
    canDeleteSessions: true,
    canManageUsers: true,
    canViewAuditLog: true,
    canViewSystemStatus: true,
    canManageConfig: true,
  },
  user: {
    canViewOwnSessions: true,
    canViewAllSessions: false,
    canSendMessages: true,
    canDeleteSessions: false,
    canManageUsers: false,
    canViewAuditLog: false,
    canViewSystemStatus: false,
    canManageConfig: false,
  },
};
```

---

## Aislamiento por Agente

Cada usuario está asociado a un `agentId`. Esto filtra automáticamente:

```typescript
// Middleware de aislamiento
async function agentIsolation(c: Context, next: Next) {
  const user = c.get('user');
  
  // Admins pueden acceder a todo
  if (user.role === 'admin') {
    return next();
  }
  
  // Usuarios normales solo ven su agente
  const requestedAgentId = c.req.param('agentId') || 
                           c.req.query('agentId');
  
  if (requestedAgentId && requestedAgentId !== user.agentId) {
    return c.json({ error: 'Forbidden' }, 403);
  }
  
  // Inyectar filtro de agente
  c.set('agentFilter', user.agentId);
  
  return next();
}
```

### Ejemplo: Listar Sesiones

```typescript
// Usuario "carlos" con agentId "carlos"
GET /api/sessions

// Solo devuelve sesiones donde:
// session.key.startsWith('agent:carlos:')
```

---

## Rate Limiting

### Límites por Endpoint

```typescript
const RATE_LIMITS = {
  // Auth
  'POST /api/auth/login': {
    points: 5,      // 5 intentos
    duration: 60,   // por minuto
    blockDuration: 300, // bloqueo de 5 min si excede
  },
  
  // Mensajes
  'POST /api/messages/send': {
    points: 30,
    duration: 60,
  },
  
  // Uploads
  'POST /api/messages/upload': {
    points: 10,
    duration: 60,
  },
  
  // WebSocket messages
  'ws:message': {
    points: 60,
    duration: 60,
  },
  
  // API general
  'default': {
    points: 100,
    duration: 60,
  },
};
```

### Implementación

```typescript
import { rateLimiter } from 'hono-rate-limiter';

app.use('*', rateLimiter({
  windowMs: 60 * 1000,
  limit: 100,
  keyGenerator: (c) => {
    // Por usuario autenticado o IP
    const user = c.get('user');
    return user?.id || c.req.header('x-forwarded-for') || 'anonymous';
  },
}));
```

---

## Seguridad de Contraseñas

### Hashing

```typescript
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### Requisitos de Contraseña

```typescript
const PASSWORD_REQUIREMENTS = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: false,  // Opcional pero recomendado
  requireNumber: false,
  requireSpecial: false,
};

function validatePassword(password: string): boolean {
  if (password.length < PASSWORD_REQUIREMENTS.minLength) return false;
  if (password.length > PASSWORD_REQUIREMENTS.maxLength) return false;
  return true;
}
```

---

## Seguridad de WebSocket

### Autenticación

```typescript
// Primera conexión requiere token
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'connect',
    token: jwtToken,
  }));
};

// Servidor valida antes de aceptar
wss.on('connection', async (ws, req) => {
  const timeout = setTimeout(() => ws.close(), 5000);
  
  ws.once('message', async (data) => {
    clearTimeout(timeout);
    
    const msg = JSON.parse(data);
    if (msg.type !== 'connect' || !msg.token) {
      ws.close(4001, 'Authentication required');
      return;
    }
    
    try {
      const user = await verifyJWT(msg.token);
      ws.user = user;
      ws.send(JSON.stringify({ type: 'connected' }));
    } catch {
      ws.close(4002, 'Invalid token');
    }
  });
});
```

### Validación de Suscripciones

```typescript
ws.on('message', async (data) => {
  const msg = JSON.parse(data);
  
  if (msg.type === 'subscribe') {
    // Validar que el usuario puede ver estas sesiones
    const allowed = msg.sessionKeys.filter(key => 
      canAccessSession(ws.user, key)
    );
    
    ws.subscriptions = allowed;
    ws.send(JSON.stringify({
      type: 'subscribed',
      sessionKeys: allowed,
    }));
  }
});
```

---

## Headers de Seguridad

```typescript
import { secureHeaders } from 'hono/secure-headers';

app.use('*', secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    connectSrc: ["'self'", "wss:"],
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  strictTransportSecurity: 'max-age=31536000; includeSubDomains',
}));
```

---

## Audit Logging

### Eventos Registrados

```typescript
type AuditEvent = {
  timestamp: number;
  userId: string;
  action: AuditAction;
  resource: string;
  details?: Record<string, unknown>;
  ip: string;
  userAgent: string;
};

type AuditAction =
  | 'login'
  | 'logout'
  | 'login_failed'
  | 'session_view'
  | 'message_send'
  | 'session_delete'
  | 'user_create'
  | 'user_update'
  | 'user_delete'
  | 'config_change';
```

### Almacenamiento

```sql
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  user_id TEXT,
  action TEXT NOT NULL,
  resource TEXT,
  details TEXT,
  ip TEXT,
  user_agent TEXT
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
```

---

## Checklist de Seguridad

### Antes de Producción

- [ ] Cambiar `JWT_SECRET` por un valor seguro y aleatorio
- [ ] Configurar `OPENCLAW_GATEWAY_TOKEN`
- [ ] Crear usuario admin con contraseña fuerte
- [ ] Habilitar HTTPS (Caddy/nginx reverse proxy)
- [ ] Configurar rate limiting apropiado
- [ ] Revisar permisos de archivos de configuración
- [ ] Configurar backups de SQLite

### Monitoreo Continuo

- [ ] Revisar audit logs regularmente
- [ ] Monitorear intentos de login fallidos
- [ ] Alertas de rate limit excedido
- [ ] Rotación periódica de tokens/secrets

---

## Siguiente: [Configuration](configuration.md) | [API Reference](api-reference.md)
