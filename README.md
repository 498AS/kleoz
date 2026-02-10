# kleoz

Implementación funcional inicial de **kleoz** con foco en:

- Multi-tasking por sesiones simultáneas.
- Sincronización realtime por WebSocket (múltiples tabs ven lo mismo).
- Sesiones compartidas tipo multiplayer.
- Respuesta del agente solo cuando el mensaje incluye `@agent`.

## Stack implementado

- **Runtime**: Bun.
- **Backend**: Hono + WebSocket + TypeScript.
- **Frontend**: React + Vite + TypeScript.
- **Auth**: JWT con usuario admin por defecto (`admin` / `admin1234`).
- **Persistencia**: SQLite (via `bun:sqlite`) + uploads en disco.

## Estructura

- `packages/api`: API REST + WebSocket.
- `packages/web`: Cliente web de chat multi-sesión.

## Desarrollo

```bash
bun install
bun run dev
```

- API: `http://localhost:3000`
- Web: `http://localhost:5173`

## Tests

```bash
bun run test
```

## Estado del proyecto

Esta entrega crea una base limpia y escalable para seguir iterando en todas las áreas descritas en `docs/`.
