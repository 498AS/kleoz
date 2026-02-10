# kleoz

Implementación funcional inicial de **kleoz** con foco en:

- Multi-tasking por sesiones simultáneas.
- Sincronización realtime por WebSocket (múltiples tabs ven lo mismo).
- Sesiones compartidas tipo multiplayer.
- Respuesta del agente solo cuando el mensaje incluye `@agent`.

## Stack implementado

- **Backend**: Hono + WebSocket + TypeScript.
- **Frontend**: React + Vite + TypeScript.
- **Auth**: JWT con usuario admin por defecto (`admin` / `admin1234`).
- **Persistencia**: In-memory (base lista para evolucionar a SQLite).

## Estructura

- `packages/api`: API REST + WebSocket.
- `packages/web`: Cliente web de chat multi-sesión.

## Desarrollo

```bash
npm install
npm run dev
```

- API: `http://localhost:3000`
- Web: `http://localhost:5173`

## Tests

```bash
npm test
```

## Estado del proyecto

Esta entrega crea una base limpia y escalable para seguir iterando en todas las áreas descritas en `docs/`.
