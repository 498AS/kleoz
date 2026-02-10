import { useMemo, useState } from 'react';
import type { PresenceEntry, SessionSummary } from '@kleoz/contracts';

import type { WsClientState } from '@/lib/wsClient';
import { cn } from '@/lib/utils';

import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInput,
  SidebarMenu,
  SidebarMenuAction,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarSeparator,
} from '@/components/ui/sidebar';

import { MessageSquareText, Monitor, Search, Trash2, Wifi, WifiOff } from 'lucide-react';

export function AppSidebar(props: {
  user: { id: string; username: string; agentId: string; role: 'admin' | 'user'; createdAt: string };
  sessions: SessionSummary[];
  activeSessionKey: string;
  onSelectSession: (k: string) => void;
  onRequestDelete: (k: string) => void;
  wsState: WsClientState;
  presenceList: PresenceEntry[];
  presenceMeta: { gatewayUptime?: number; timestamp?: number };
}) {
  const [query, setQuery] = useState<string>('');

  const filteredSessions = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return props.sessions;
    return props.sessions.filter((s) => {
      const title = (s.displayName || s.channel || s.key || '').toLowerCase();
      return title.includes(q) || s.key.toLowerCase().includes(q);
    });
  }, [props.sessions, query]);

  const ws = props.wsState;
  const wsLabel = ws.status === 'open' ? 'WS conectado' : ws.status === 'connecting' ? 'WS conectando' : ws.status === 'error' ? 'WS error' : 'WS offline';

  return (
    <Sidebar variant="inset" collapsible="icon">
      <SidebarHeader className="gap-2">
        <div className="flex items-center gap-2 px-1">
          <Avatar className="h-8 w-8">
            <AvatarFallback className="text-xs">{initials(props.user.username)}</AvatarFallback>
          </Avatar>
          <div className="min-w-0 flex-1 group-data-[collapsible=icon]:hidden">
            <div className="truncate text-sm font-medium">{props.user.username}</div>
            <div className="truncate text-xs text-muted-foreground">{props.user.role}</div>
          </div>
          <Badge
            variant={ws.status === 'open' ? 'secondary' : ws.status === 'error' ? 'destructive' : 'outline'}
            className="gap-1"
            title={wsLabel}
          >
            {ws.status === 'open' ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
            <span className="hidden xl:inline">WS</span>
          </Badge>
        </div>

        <div className="relative px-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <SidebarInput
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar sesiones..."
            className="pl-9"
          />
        </div>

        <SidebarSeparator />
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Sesiones</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {filteredSessions.map((s) => {
                const title = s.displayName || s.channel || s.key;
                const isActive = s.key === props.activeSessionKey;
                const status = s.status ?? 'idle';
                return (
                  <SidebarMenuItem key={s.key}>
                    <SidebarMenuButton asChild isActive={isActive} tooltip={title}>
                      <button onClick={() => props.onSelectSession(s.key)}>
                        <MessageSquareText className="h-4 w-4" />
                        <span className="truncate">{title}</span>
                      </button>
                    </SidebarMenuButton>
                    <SidebarMenuBadge className={cn(status === 'idle' ? 'text-muted-foreground' : '')}>{status}</SidebarMenuBadge>
                    <SidebarMenuAction onClick={() => props.onRequestDelete(s.key)} title="Eliminar">
                      <Trash2 className="h-4 w-4" />
                    </SidebarMenuAction>
                  </SidebarMenuItem>
                );
              })}
              {filteredSessions.length === 0 ? (
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <div className="text-xs text-muted-foreground">Sin sesiones</div>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ) : null}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>
            Presence <span className="text-muted-foreground">({props.presenceList.length})</span>
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {props.presenceList.slice(0, 12).map((p) => (
                <SidebarMenuItem key={p.instanceId}>
                  <SidebarMenuButton asChild tooltip={p.instanceId}>
                    <div className="flex w-full items-center gap-2">
                      <Monitor className="h-4 w-4" />
                      <span className="truncate">{p.host}</span>
                      <span className="ml-auto text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">{p.mode}</span>
                    </div>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
              {props.presenceList.length === 0 ? (
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <div className="text-xs text-muted-foreground">Sin presencia</div>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ) : null}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <div className="flex items-center justify-between gap-2 px-2 pb-2 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">
          <span>{wsLabel}</span>
          {props.presenceMeta.timestamp ? <span>{new Date(props.presenceMeta.timestamp).toLocaleTimeString()}</span> : null}
        </div>
        <div className="px-2 pb-2 group-data-[collapsible=icon]:hidden">
          <Button variant="ghost" size="sm" className="w-full justify-start" asChild>
            <a href="#" onClick={(e) => e.preventDefault()}>
              {props.user.agentId ? <span className="font-mono text-xs">agent: {props.user.agentId}</span> : <span className="text-xs">agent</span>}
            </a>
          </Button>
        </div>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  );
}

function initials(username: string): string {
  const clean = (username || '').trim();
  if (!clean) return 'U';
  const parts = clean.split(/\s+/g).filter(Boolean);
  const first = parts[0]?.[0] ?? 'U';
  const second = parts[1]?.[0] ?? parts[0]?.[1] ?? '';
  return (first + second).toUpperCase();
}
