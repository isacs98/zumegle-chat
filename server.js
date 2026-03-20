const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const helmet = require('helmet');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e5
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, 'public')));

const MSG_MAX_LENGTH = 500;
const MAX_CONNECTIONS_PER_IP = 4;
const SPAM_THRESHOLD = 100;
const TAGS_MAX = 10;
const TAG_MAX_LENGTH = 30;
const MAX_VIOLATIONS = 3;

// Vendas e spam comercial
const PALAVRAS_VENDAS = [
    'onlyfans','privacy','compre agora','vendo','promoção','desconto',
    'ganhar dinheiro','renda extra','trabalhe em casa','oportunidade de negócio',
    'whatsapp','telegram','instagram','tiktok','twitter','facebook',
    'snapchat','kwai','seguidores',
];

// Links e URLs
const PALAVRAS_LINKS = [
    'http://','https://','www.','bit.ly','tinyurl','t.me','wa.me',
];

// Crime e conteúdo ilegal
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

function verificarMensagem(msg) {
    const msgLower = msg.toLowerCase();
    let msgCensurada = msg;
    let temViolacao = false;

    for (const palavra of TODAS_PALAVRAS_PROIBIDAS) {
        if (msgLower.includes(palavra.toLowerCase())) {
            temViolacao = true;
            const regex = new RegExp(palavra.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
            msgCensurada = msgCensurada.replace(regex, '***');
        }
    }

    return { temViolacao, msgCensurada };
}

const bannedIPs = new Set();
const flaggedIPs = new Set();
const reportedIPs = new Map();
const userLastMessage = new Map();
const activeRooms = new Map();
const userIPs = new Map();
const connectionsPerIP = new Map();
const violacoesUsuario = new Map();
const messageTimes = new Map();    // Rate limit: timestamps das msgs por socket
const RATE_LIMIT_MSGS = 5;         // Max mensagens
const RATE_LIMIT_WINDOW = 3000;    // em 3 segundos

let waitingQueue = [];
let totalOnlineUsers = 0;

setInterval(() => {
    reportedIPs.clear();
    console.log('🧹 Limpeza diária de memória efetuada.');
}, 24 * 60 * 60 * 1000);

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

    socket.on('start_chat', (data) => {
        if (activeRooms.has(socket.id)) return;

        const captchaToken = data?.captchaToken || data;
        const userTags = sanitizeTags(data?.tags);

        if (flaggedIPs.has(ip)) {
            if (!captchaToken || typeof captchaToken !== 'string') {
                socket.emit('captcha_required');
                return;
            }

            const secretKey = process.env.RECAPTCHA_SECRET_KEY || '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
            const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaToken}`;

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

        // ── VERIFICAÇÃO DE PALAVRAS PROIBIDAS ─────────────────────────────────
        const { temViolacao, msgCensurada } = verificarMensagem(trimmed);

        if (temViolacao) {
            const violacoes = (violacoesUsuario.get(socket.id) || 0) + 1;
            violacoesUsuario.set(socket.id, violacoes);

            console.log(`⚠️ Violação ${violacoes}/${MAX_VIOLATIONS} - IP: ${currentIp}`);

            if (violacoes >= MAX_VIOLATIONS) {
                bannedIPs.add(currentIp);
                console.log(`🚫 IP banido por violações repetidas: ${currentIp}`);
                setTimeout(() => {
                    handleDisconnect(socket);
                    socket.disconnect();
                }, 2000);
            }

            // Quem enviou: não recebe aviso (não sabe que foi bloqueado)
            // Quem recebe: vê a mensagem censurada + aviso
            socket.to(room).emit('receive_message', msgCensurada);
            socket.to(room).emit('system_message', '⚠️ Parte da mensagem foi ocultada por violar as regras da plataforma.');
            return;
        }

        // ── RATE LIMIT (velocidade de mensagens) ─────────────────────────────
        const now = Date.now();
        const times = (messageTimes.get(socket.id) || []).filter(t => now - t < RATE_LIMIT_WINDOW);
        times.push(now);
        messageTimes.set(socket.id, times);

        if (times.length > RATE_LIMIT_MSGS) {
            flaggedIPs.add(currentIp);
            console.log(`⚡ Rate limit atingido - IP: ${currentIp}`);
            return; // Descarta a mensagem silenciosamente
        }

        // ── DETECÇÃO DE SPAM ──────────────────────────────────────────────────
        const lastMsgObj = userLastMessage.get(socket.id);
        if (lastMsgObj && lastMsgObj.text === trimmed) {
            lastMsgObj.count++;
            if (lastMsgObj.count >= SPAM_THRESHOLD) {
                flaggedIPs.add(currentIp);
            }
        } else {
            userLastMessage.set(socket.id, { text: trimmed, count: 1 });
        }

        socket.to(room).emit('receive_message', trimmed);
    });

    socket.on('stop_chat', () => handleDisconnect(socket));

    socket.on('report_user', () => {
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
                        if (currentReports >= 3) {
                            bannedIPs.add(strangerIP);
                            console.log(`🚫 IP banido por múltiplos reports: ${strangerIP}`);
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
        handleDisconnect(socket);
    });

    function handleDisconnect(sock) {
        waitingQueue = waitingQueue.filter(u => u.socket.id !== sock.id);

        const room = activeRooms.get(sock.id);
        if (room) {
            sock.to(room).emit('stranger_disconnected');
            const clients = io.sockets.adapter.rooms.get(room);
            if (clients) {
                for (const clientId of clients) {
                    activeRooms.delete(clientId);
                    const clientSocket = io.sockets.sockets.get(clientId);
                    if (clientSocket) clientSocket.leave(room);
                }
            }
        }
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor a correr na porta ${PORT}`);
});
