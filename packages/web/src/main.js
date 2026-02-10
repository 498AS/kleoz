import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { StrictMode, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
function App() {
    const [token, setToken] = useState('');
    const [user, setUser] = useState(null);
    const [sessions, setSessions] = useState([]);
    const [activeKey, setActiveKey] = useState('');
    const [messagesBySession, setMessagesBySession] = useState({});
    const wsRef = useRef(null);
    const activeMessages = useMemo(() => messagesBySession[activeKey] ?? [], [messagesBySession, activeKey]);
    useEffect(() => {
        if (!token)
            return;
        fetch('/api/sessions', { headers: { Authorization: `Bearer ${token}` } })
            .then((r) => r.json())
            .then((d) => {
            setSessions(d.sessions ?? []);
            if (d.sessions?.length && !activeKey)
                setActiveKey(d.sessions[0].key);
        });
    }, [token, activeKey]);
    useEffect(() => {
        if (!token)
            return;
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${wsProtocol}//${window.location.host}/api/ws?token=${encodeURIComponent(token)}`);
        wsRef.current = ws;
        ws.onmessage = (event) => {
            const payload = JSON.parse(event.data);
            if (payload.type === 'message.complete') {
                setMessagesBySession((prev) => ({
                    ...prev,
                    [payload.sessionKey]: [...(prev[payload.sessionKey] ?? []), payload.message],
                }));
            }
        };
        return () => ws.close();
    }, [token]);
    useEffect(() => {
        if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
            const timer = setInterval(() => {
                if (wsRef.current?.readyState === WebSocket.OPEN) {
                    wsRef.current.send(JSON.stringify({ type: 'sessions.subscribe', sessionKeys: sessions.map((s) => s.key) }));
                    clearInterval(timer);
                }
            }, 100);
            return () => clearInterval(timer);
        }
        wsRef.current.send(JSON.stringify({ type: 'sessions.subscribe', sessionKeys: sessions.map((s) => s.key) }));
    }, [sessions]);
    async function login(formData) {
        const username = formData.get('username');
        const password = formData.get('password');
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        if (!res.ok)
            return;
        const out = await res.json();
        setToken(out.token);
        setUser(out.user);
    }
    async function sendMessage(formData) {
        const message = String(formData.get('message') ?? '');
        if (!message || !activeKey)
            return;
        await fetch('/api/messages/send', {
            method: 'POST',
            headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ sessionKey: activeKey, message }),
        });
    }
    async function createSession(formData) {
        const name = String(formData.get('name') ?? '').trim();
        if (!name)
            return;
        const key = `agent:${user?.agentId ?? 'main'}:shared:${name}`;
        await fetch('/api/messages/send', {
            method: 'POST',
            headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ sessionKey: key, message: 'Sesión creada', participants: [user?.id] }),
        });
        setSessions((prev) => (prev.find((p) => p.key === key) ? prev : [...prev, { key, title: name }]));
        setActiveKey(key);
    }
    if (!token) {
        return (_jsxs("main", { className: "container", children: [_jsx("h1", { children: "kleoz" }), _jsx("p", { children: "Login demo (admin/admin1234)" }), _jsxs("form", { action: login, className: "panel", children: [_jsx("input", { name: "username", placeholder: "username", defaultValue: "admin" }), _jsx("input", { name: "password", type: "password", placeholder: "password", defaultValue: "admin1234" }), _jsx("button", { children: "Entrar" })] })] }));
    }
    return (_jsxs("main", { className: "layout", children: [_jsxs("aside", { children: [_jsx("h2", { children: user?.username }), _jsxs("form", { action: createSession, className: "inline", children: [_jsx("input", { name: "name", placeholder: "nueva sesi\u00F3n" }), _jsx("button", { children: "+" })] }), sessions.map((s) => (_jsx("button", { onClick: () => setActiveKey(s.key), className: s.key === activeKey ? 'active' : '', children: s.title }, s.key)))] }), _jsxs("section", { children: [_jsx("header", { children: activeKey || 'Selecciona sesión' }), _jsx("div", { className: "messages", children: activeMessages.map((m) => (_jsxs("article", { children: [_jsx("b", { children: m.sender }), ": ", m.body] }, m.id))) }), _jsxs("form", { action: sendMessage, className: "inline", children: [_jsx("input", { name: "message", placeholder: "Escribe... usa @agent para respuesta" }), _jsx("button", { children: "Enviar" })] })] })] }));
}
createRoot(document.getElementById('root')).render(_jsx(StrictMode, { children: _jsx(App, {}) }));
