# kleoz

<p align="center">
  <img src="docs/assets/logo-placeholder.svg" alt="kleoz" width="200">
</p>

<p align="center">
  <strong>Multi-Agent Chat Interface for OpenClaw</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#stack">Stack</a> •
  <a href="#documentation">Docs</a> •
  <a href="#roadmap">Roadmap</a>
</p>

---

## Overview

**kleoz** is a web-based multi-agent chat interface built on top of [OpenClaw Gateway](https://github.com/openclaw/openclaw). It provides a unified dashboard for managing AI agent sessions with per-agent authentication, real-time sync, and full multimedia support.

### Why kleoz?

- **Per-agent authentication**: Each agent has its own credentials. Users only see sessions they're authorized for.
- **Real-time multi-tasking**: Multiple chat sessions running in parallel with WebSocket-based instant updates.
- **Full OpenClaw sync**: JSONL transcripts are the source of truth. Nothing is duplicated.
- **Complete media support**: Send and receive files, images, audio — drag & drop native.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔐 **Agent Auth** | Username/password per agent. Granular permissions. |
| ⚡ **Multi-session** | Open multiple chats simultaneously. Multiplexed WebSocket. |
| 🔄 **Real-time Sync** | Messages stream instantly. Session state always fresh. |
| 📎 **Rich Media** | Images, files, audio. Inline preview. Drag & drop. |
| 👁️ **Admin + User Views** | Debug mode for devs. Clean UI for end users. |
| 🌙 **Dark Mode** | Native dark theme. Easy on the eyes. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        FRONTEND                             │
│  React + TanStack Router + TanStack Query + Zustand         │
│  Shadcn/ui + Tailwind CSS                                   │
└─────────────────────┬───────────────────────────────────────┘
                      │ HTTP/WebSocket
┌─────────────────────▼───────────────────────────────────────┐
│                        BACKEND                              │
│  Hono + TypeScript                                          │
│  • JWT Authentication                                       │
│  • Session management                                       │
│  • WebSocket multiplexing                                   │
│  • SQLite (users, cache)                                    │
└─────────────────────┬───────────────────────────────────────┘
                      │ Internal RPC
┌─────────────────────▼───────────────────────────────────────┐
│                   OPENCLAW GATEWAY                          │
│  • sessions_list / sessions_history                         │
│  • sessions_send                                            │
│  • Transcript JSONL files (source of truth)                 │
│  • Concurrency: 4 sessions/agent, 8 subagents               │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. User authenticates → JWT token issued
2. Frontend opens WebSocket → subscribes to sessions
3. User sends message → API forwards to OpenClaw Gateway
4. Gateway runs agent → streams response back via WebSocket
5. Frontend updates in real-time

---

## Stack

### Frontend

| Technology | Purpose |
|------------|---------|
| [React 19](https://react.dev/) | UI framework |
| [TanStack Router](https://tanstack.com/router) | Type-safe file-based routing |
| [TanStack Query](https://tanstack.com/query) | Data fetching, caching, sync |
| [Zustand](https://zustand-demo.pmnd.rs/) | Lightweight state management |
| [Shadcn/ui](https://ui.shadcn.com/) | Accessible component primitives |
| [Tailwind CSS](https://tailwindcss.com/) | Utility-first styling |
| [TanStack Virtual](https://tanstack.com/virtual) | Virtualized lists (long histories) |

### Backend

| Technology | Purpose |
|------------|---------|
| [Hono](https://hono.dev/) | Ultrafast web framework |
| [TypeScript](https://www.typescriptlang.org/) | End-to-end type safety |
| [SQLite](https://www.sqlite.org/) | Users, sessions cache |
| [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) | Sync SQLite driver |
| JWT | Stateless authentication |

### Infrastructure

| Component | Details |
|-----------|---------|
| Runtime | Node.js 22+ |
| OpenClaw | Gateway on port 18789 |
| Deploy | Same server as OpenClaw |

---

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/api-reference.md) | REST endpoints, WebSocket events, error codes |
| [Sessions](docs/sessions.md) | Session types, lifecycle, sync with OpenClaw |
| [Tools](docs/tools.md) | Available agent tools (exec, browser, web, nodes) |
| [Configuration](docs/configuration.md) | Project setup, env vars, Docker, database |
| [Presence](docs/presence.md) | Real-time user/device presence system |
| [Security](docs/security.md) | Auth, permissions, rate limiting |

---

## Project Structure

```
kleoz/
├── packages/
│   ├── api/                    # Hono backend
│   │   ├── src/
│   │   │   ├── routes/         # REST endpoints
│   │   │   ├── ws/             # WebSocket handlers
│   │   │   ├── middleware/     # Auth, logging
│   │   │   ├── services/       # Business logic
│   │   │   ├── db/             # SQLite schemas
│   │   │   └── gateway/        # OpenClaw client
│   │   └── package.json
│   │
│   └── web/                    # React frontend
│       ├── src/
│       │   ├── routes/         # TanStack Router pages
│       │   ├── components/     # UI components
│       │   ├── hooks/          # Custom hooks
│       │   ├── stores/         # Zustand stores
│       │   └── lib/            # Utilities
│       └── package.json
│
├── docs/                       # Documentation
├── docker-compose.yml
└── package.json
```

---

## Roadmap

### Phase 1: Core (Current)
- [ ] Project scaffolding
- [ ] Auth system (JWT + SQLite)
- [ ] OpenClaw Gateway client
- [ ] Session list view
- [ ] Basic chat UI

### Phase 2: Real-time
- [ ] WebSocket infrastructure
- [ ] Message streaming
- [ ] Presence system
- [ ] Multi-session tabs

### Phase 3: Media & Polish
- [ ] File upload/download
- [ ] Image preview
- [ ] Tool call visualization
- [ ] Admin dashboard

### Phase 4: Production
- [ ] Docker deployment
- [ ] Rate limiting
- [ ] Audit logging
- [ ] Performance optimization

---

## Quick Start (Coming Soon)

```bash
# Clone the repo
git clone https://github.com/498-as/kleoz.git
cd kleoz

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your OpenClaw gateway details

# Start development
npm run dev
```

---

## Requirements

- Node.js 22+
- OpenClaw Gateway running on the same server
- SQLite (bundled)

---

## Related Projects

- [OpenClaw](https://github.com/openclaw/openclaw) — The AI assistant platform this is built on
- [OpenClaw Docs](https://docs.openclaw.ai) — Official OpenClaw documentation

---

## License

MIT

---

## Credits

Built by [498Advance](https://498as.com) 🦁
