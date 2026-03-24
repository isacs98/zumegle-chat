const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const helmet = require('helmet');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

// ─── CORS RESTRITO ────────────────────────────────────────────────────────────
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

const io = new Server(server, {
    maxHttpBufferSize: 1e5,
    cors: {
        origin: ALLOWED_ORIGIN,
        methods: ['GET', 'POST'],
        credentials: true
    }
});

// ─── HELMET COM CSP CONFIGURADO (não desabilitado) ───────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",           // socket.io inline + recaptcha inline
                "https://www.google.com",
                "https://www.gstatic.com",
                "https://fonts.googleapis.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "https://images.unsplash.com",
                "https://www.google.com",
                "https://www.gstatic.com"
            ],
            frameSrc: [
                "https://www.google.com"     // reCAPTCHA iframe
            ],
            connectSrc: [
                "'self'",
                "wss:",
                "ws:"
            ],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    crossOriginOpenerPolicy: { policy: 'same-origin' }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ─── HEALTH CHECK (mantém o Render ativo) ────────────────────────────────────
app.get('/health', (req, res) => res.status(200).json({ status: 'ok', uptime: process.uptime() }));

// ─── CONSTANTES DE SEGURANÇA ──────────────────────────────────────────────────
const MSG_MAX_LENGTH       = 500;
const MAX_CONNECTIONS_PER_IP = 4;
const SPAM_THRESHOLD       = 100;
const TAGS_MAX             = 10;
const TAG_MAX_LENGTH       = 30;
const MAX_VIOLATIONS       = 3;
const RATE_LIMIT_MSGS      = 5;
const RATE_LIMIT_WINDOW    = 3000;   // 3 segundos
const INACTIVITY_TIMEOUT   = 10 * 60 * 1000; // 10 minutos sem mensagens
const START_CHAT_COOLDOWN  = 2000;   // debounce para start_chat

// ─── FILTROS DE PALAVRAS PROIBIDAS ───────────────────────────────────────────
const PALAVRAS_VENDAS = [
    'onlyfans','privacy','compre','compra','vendo','venda','vende',
    'venda de','vendendo','pack','packs','promoção','promocao','desconto',
    'ganhar dinheiro','renda extra','trabalhe em casa','oportunidade de negócio',
    'whatsapp','wpp','zap','telegram','instagram','insta','tiktok',
    'twitter','facebook','snapchat','kwai','seguidores','divulg',
    'acessa','acesse','entra no','entre no',
];

const PALAVRAS_LINKS = [
    'http://','https://','www.','bit.ly','tinyurl','t.me','wa.me',
];

const PALAVRAS_CRIME = [
    'tráfico','trafico','cocaína','cocaina','maconha','crack','heroína',
    'heroina','ecstasy','arma de fogo','pistola à venda','fuzil',
    'matar alguém','sequestro','extorsão','extorsao','lavagem de dinheiro',
    'pedofilia','pedófilo','pedofilo','criança nua','crianca nua','csam',
    'abuso sexual infantil','cartão clonado','cartao clonado',
    'documento falso','identidade falsa','hackear conta',
];

const TODAS_PALAVRAS_PROIBIDAS = [
    ...PALAVRAS_VENDAS,
    ...PALAVRAS_LINKS,
    ...PALAVRAS_CRIME,
];

// Normaliza texto: remove espaços entre letras e caracteres especiais
// Ex: "w h a t s a p p" → "whatsapp"
function normalizarTexto(str) {
    return str
        .toLowerCase()
        .replace(/\s+/g, '')                     // remove todos os espaços
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '');         // remove acentos
}

function verificarMensagem(msg) {
    const msgNormal = normalizarTexto(msg);
    const msgLower  = msg.toLowerCase();
    let msgCensurada = msg;
    let temViolacao  = false;

    for (const palavra of TODAS_PALAVRAS_PROIBIDAS) {
        const palavraNormal = normalizarTexto(palavra);
        if (msgNormal.includes(palavraNormal) || msgLower.includes(palavra.toLowerCase())) {
            temViolacao = true;
            const regex = new RegExp(palavra.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
            msgCensurada = msgCensurada.replace(regex, '***');
        }
    }

    return { temViolacao, msgCensurada };
}

// ─── ESTADO ───────────────────────────────────────────────────────────────────
const bannedIPs            = new Set();
const flaggedIPs           = new Set();
const reportedIPs          = new Map();
const userLastMessage      = new Map();
const activeRooms          = new Map();
const userIPs              = new Map();
const connectionsPerIP     = new Map();
const violacoesUsuario     = new Map();
const messageTimes         = new Map();
const inactivityTimers     = new Map();  // timeout de inatividade por sala
const startChatLastTime    = new Map();  // debounce de start_chat por socket
const reportedBySocket     = new Set();  // report já feito por socket (evita flood)

let waitingQueue     = [];
let totalOnlineUsers = 0;

// ─── LOG DE MODERAÇÃO (arquivo) ───────────────────────────────────────────────
const LOG_FILE = path.join(__dirname, 'moderation.log');

function logMod(tipo, ip, extra = '') {
    const linha = `[${new Date().toISOString()}] [${tipo}] IP:${ip} ${extra}\n`;
    console.log(linha.trim());
    fs.appendFile(LOG_FILE, linha, () => {});  // async, sem travar o loop
}

// ─── LIMPEZA DIÁRIA ───────────────────────────────────────────────────────────
setInterval(() => {
    reportedIPs.clear();
    logMod('LIMPEZA', 'sistema', 'reportedIPs limpos');
}, 24 * 60 * 60 * 1000);

// ─── UTILITÁRIOS ──────────────────────────────────────────────────────────────
function getIP(socket) {
    let ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    return ip;
}

function sanitizeTags(raw) {
    if (!Array.isArray(raw)) return [];
    return raw
        .map(t => String(t).trim().toLowerCase().replace(/[^a-záàâãéèêíïóôõöúçñ0-9 _-]/gi, ''))
        .filter(t => t.length > 0 && t.length <= TAG_MAX_LENGTH)
        .slice(0, TAGS_MAX);
}

// ─── TIMEOUT DE INATIVIDADE ───────────────────────────────────────────────────
function resetInactivityTimer(room) {
    if (inactivityTimers.has(room)) {
        clearTimeout(inactivityTimers.get(room));
    }
    const t = setTimeout(() => {
        const clients = io.sockets.adapter.rooms.get(room);
        if (clients) {
            for (const clientId of clients) {
                const s = io.sockets.sockets.get(clientId);
                if (s) {
                    s.emit('system_message', '⏱️ Sessão encerrada por inatividade (10 minutos sem mensagens).');
                    handleDisconnect(s);
                }
            }
        }
        inactivityTimers.delete(room);
    }, INACTIVITY_TIMEOUT);
    inactivityTimers.set(room, t);
}

function clearInactivityTimer(room) {
    if (inactivityTimers.has(room)) {
        clearTimeout(inactivityTimers.get(room));
        inactivityTimers.delete(room);
    }
}

// ─── SOCKET.IO ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    const ip = getIP(socket);
    userIPs.set(socket.id, ip);

    if (bannedIPs.has(ip)) {
        socket.emit('system_message', 'ACESSO NEGADO: Foste banido permanentemente dos nossos servidores por múltiplas violações dos Termos de Serviço.');
        socket.disconnect();
        return;
    }

    const currentConns = connectionsPerIP.get(ip) || 0;
    if (currentConns >= MAX_CONNECTIONS_PER_IP) {
        socket.emit('system_message', 'Demasiadas conexões do mesmo dispositivo. Fecha outras abas e tenta novamente.');
        socket.disconnect();
        return;
    }

    connectionsPerIP.set(ip, currentConns + 1);
    violacoesUsuario.set(socket.id, 0);

    totalOnlineUsers++;
    io.emit('online_count', totalOnlineUsers);

    // ── start_chat com debounce server-side ───────────────────────────────────
    socket.on('start_chat', (data) => {
        // Evita spam de start_chat
        const now = Date.now();
        const last = startChatLastTime.get(socket.id) || 0;
        if (now - last < START_CHAT_COOLDOWN) return;
        startChatLastTime.set(socket.id, now);

        if (activeRooms.has(socket.id)) return;

        const captchaToken = data?.captchaToken || data;
        const userTags = sanitizeTags(data?.tags);

        if (flaggedIPs.has(ip)) {
            if (!captchaToken || typeof captchaToken !== 'string') {
                socket.emit('captcha_required');
                return;
            }

            const secretKey = process.env.RECAPTCHA_SECRET_KEY;
            if (!secretKey) {
                // Sem chave configurada: deixa passar mas loga o aviso
                logMod('AVISO', ip, 'RECAPTCHA_SECRET_KEY não configurada — captcha ignorado');
                executeMatchmaking(socket, userTags);
                return;
            }

            const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${encodeURIComponent(captchaToken)}`;

            https.get(url, (res) => {
                let chunkData = '';
                res.on('data', (chunk) => chunkData += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(chunkData);
                        if (result.success) {
                            executeMatchmaking(socket, userTags);
                        } else {
                            socket.emit('system_message', 'Falha na verificação do Captcha. Tenta novamente.');
                        }
                    } catch (e) {
                        socket.emit('system_message', 'Erro interno ao validar Captcha.');
                    }
                });
            }).on('error', () => {
                socket.emit('system_message', 'Falha na comunicação com o sistema de segurança.');
            });
        } else {
            executeMatchmaking(socket, userTags);
        }
    });

    function executeMatchmaking(socket, tags) {
        let matchIndex = -1;
        let commonTags = [];

        if (tags && tags.length > 0) {
            matchIndex = waitingQueue.findIndex(u => {
                if (!u.tags) return false;
                const intersection = u.tags.filter(t => tags.includes(t));
                if (intersection.length > 0) {
                    commonTags = intersection;
                    return true;
                }
                return false;
            });
        }

        if (matchIndex === -1) {
            matchIndex = waitingQueue.length > 0 ? 0 : -1;
            commonTags = [];
        }

        if (matchIndex !== -1) {
            const partner = waitingQueue.splice(matchIndex, 1)[0];
            const partnerSocket = partner.socket;
            const roomName = `room_${partnerSocket.id}_${socket.id}`;

            socket.join(roomName);
            partnerSocket.join(roomName);

            activeRooms.set(socket.id, roomName);
            activeRooms.set(partnerSocket.id, roomName);

            resetInactivityTimer(roomName);

            io.to(socket.id).emit('chat_started', { commonTags });
            io.to(partnerSocket.id).emit('chat_started', { commonTags });
        } else {
            waitingQueue.push({ socket, tags });
            socket.emit('waiting');
        }
    }

    socket.on('typing', (isTyping) => {
        const room = activeRooms.get(socket.id);
        if (room) {
            socket.to(room).emit('stranger_typing', !!isTyping);
        }
    });

    socket.on('send_message', (msg) => {
        const room = activeRooms.get(socket.id);
        if (!room) return;

        if (typeof msg !== 'string') return;
        const trimmed = msg.trim();
        if (trimmed.length === 0 || trimmed.length > MSG_MAX_LENGTH) return;

        const currentIp = userIPs.get(socket.id);

        // ── RATE LIMIT ────────────────────────────────────────────────────────
        const now = Date.now();
        const times = (messageTimes.get(socket.id) || []).filter(t => now - t < RATE_LIMIT_WINDOW);
        times.push(now);
        messageTimes.set(socket.id, times);

        if (times.length > RATE_LIMIT_MSGS) {
            flaggedIPs.add(currentIp);
            logMod('RATE_LIMIT', currentIp);
            return;
        }

        // ── DETECÇÃO DE SPAM (mensagem repetida) ──────────────────────────────
        const lastMsgObj = userLastMessage.get(socket.id);
        if (lastMsgObj && lastMsgObj.text === trimmed) {
            lastMsgObj.count++;
            if (lastMsgObj.count >= SPAM_THRESHOLD) {
                flaggedIPs.add(currentIp);
                logMod('SPAM', currentIp);
            }
        } else {
            userLastMessage.set(socket.id, { text: trimmed, count: 1 });
        }

        // ── PALAVRAS PROIBIDAS ────────────────────────────────────────────────
        const { temViolacao, msgCensurada } = verificarMensagem(trimmed);

        if (temViolacao) {
            const violacoes = (violacoesUsuario.get(socket.id) || 0) + 1;
            violacoesUsuario.set(socket.id, violacoes);
            logMod('VIOLACAO', currentIp, `${violacoes}/${MAX_VIOLATIONS}`);

            if (violacoes >= MAX_VIOLATIONS) {
                bannedIPs.add(currentIp);
                logMod('BAN', currentIp, 'violações repetidas');
                setTimeout(() => {
                    socket.emit('system_message', 'ACESSO NEGADO: Foste banido por múltiplas violações.');
                    handleDisconnect(socket);
                    socket.disconnect();
                }, 2000);
            }

            socket.to(room).emit('receive_message', msgCensurada);
            socket.to(room).emit('system_message', '⚠️ Parte da mensagem foi ocultada por violar as regras da plataforma.');
            return;
        }

        // ── RESET DO TIMER DE INATIVIDADE ─────────────────────────────────────
        resetInactivityTimer(room);

        socket.to(room).emit('receive_message', trimmed);
    });

    socket.on('stop_chat', () => handleDisconnect(socket));

    // ── REPORT COM PROTEÇÃO CONTRA FLOOD ─────────────────────────────────────
    socket.on('report_user', () => {
        if (reportedBySocket.has(socket.id)) return; // já reportou nesta sessão
        reportedBySocket.add(socket.id);

        const room = activeRooms.get(socket.id);
        if (!room) return;

        const clients = io.sockets.adapter.rooms.get(room);
        if (clients) {
            for (const clientId of clients) {
                if (clientId !== socket.id) {
                    const strangerIP = userIPs.get(clientId);
                    if (strangerIP) {
                        const currentReports = (reportedIPs.get(strangerIP) || 0) + 1;
                        reportedIPs.set(strangerIP, currentReports);
                        logMod('REPORT', strangerIP, `total=${currentReports}`);
                        if (currentReports >= 3) {
                            bannedIPs.add(strangerIP);
                            logMod('BAN', strangerIP, 'múltiplos reports');
                        }
                    }
                }
            }
        }
        handleDisconnect(socket);
    });

    socket.on('disconnect', () => {
        totalOnlineUsers = Math.max(0, totalOnlineUsers - 1);
        io.emit('online_count', totalOnlineUsers);

        const connCount = (connectionsPerIP.get(ip) || 1) - 1;
        if (connCount <= 0) {
            connectionsPerIP.delete(ip);
        } else {
            connectionsPerIP.set(ip, connCount);
        }

        userLastMessage.delete(socket.id);
        userIPs.delete(socket.id);
        violacoesUsuario.delete(socket.id);
        messageTimes.delete(socket.id);
        startChatLastTime.delete(socket.id);
        reportedBySocket.delete(socket.id);

        handleDisconnect(socket);
    });

    function handleDisconnect(sock) {
        waitingQueue = waitingQueue.filter(u => u.socket.id !== sock.id);

        const room = activeRooms.get(sock.id);
        if (room) {
            clearInactivityTimer(room);
            sock.to(room).emit('stranger_disconnected');
            const clients = io.sockets.adapter.rooms.get(room);
            if (clients) {
                for (const clientId of clients) {
                    activeRooms.delete(clientId);
                    const clientSocket = io.sockets.sockets.get(clientId);
                    if (clientSocket) clientSocket.leave(room);
                }
            }
            // Garante remoção mesmo se a sala já estiver vazia
            activeRooms.delete(sock.id);
        }
    }
});

// ─── 404 PERSONALIZADO ────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// ─── GRACEFUL SHUTDOWN ────────────────────────────────────────────────────────
function gracefulShutdown(signal) {
    console.log(`\n🛑 ${signal} recebido — encerrando servidor...`);
    io.emit('system_message', '⚠️ O servidor está a reiniciar. Reconecte em alguns segundos.');
    io.close(() => {
        server.close(() => {
            console.log('✅ Servidor encerrado com segurança.');
            process.exit(0);
        });
    });
    // Force exit após 8 segundos
    setTimeout(() => process.exit(1), 8000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor a correr na porta ${PORT}`);
    console.log(`🌍 Origin permitida: ${ALLOWED_ORIGIN}`);
    if (!process.env.RECAPTCHA_SECRET_KEY) {
        console.warn('⚠️  AVISO: RECAPTCHA_SECRET_KEY não está definida nas variáveis de ambiente!');
    }
});
