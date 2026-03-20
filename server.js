const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const helmet = require('helmet');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    // Limita o tamanho máximo de qualquer pacote Socket.io (mensagem, evento, etc.)
    maxHttpBufferSize: 1e5 // 100 KB — suficiente para uma mensagem de texto
});

// ─── SEGURANÇA HTTP ────────────────────────────────────────────────────────────
// Helmet adiciona headers de segurança (XSS, clickjacking, etc.)
// Content Security Policy desativado para não quebrar o Tailwind CDN / Google Fonts
app.use(helmet({ contentSecurityPolicy: false }));

app.use(express.static(path.join(__dirname, 'public')));

// ─── CONFIGURAÇÕES ─────────────────────────────────────────────────────────────
const MSG_MAX_LENGTH = 500;        // Máximo de caracteres por mensagem
const MAX_CONNECTIONS_PER_IP = 4;  // Máximo de abas/conexões simultâneas do mesmo IP
const SPAM_THRESHOLD = 100;        // Mensagens idênticas repetidas para marcar como spam
const TAGS_MAX = 10;               // Máximo de tags por utilizador
const TAG_MAX_LENGTH = 30;         // Máximo de caracteres por tag

// ─── ESTRUTURAS DE DADOS ───────────────────────────────────────────────────────
const bannedIPs = new Set();
const flaggedIPs = new Set();
const reportedIPs = new Map();
const userLastMessage = new Map();
const activeRooms = new Map();
const userIPs = new Map();
const connectionsPerIP = new Map(); // NOVO: controla abas simultâneas

let waitingQueue = [];
let totalOnlineUsers = 0;

// ─── LIMPEZA DE MEMÓRIA DIÁRIA ─────────────────────────────────────────────────
// Essencial para o plano gratuito do Render não estourar a memória
setInterval(() => {
    reportedIPs.clear();
    console.log('🧹 Limpeza diária de memória efetuada.');
}, 24 * 60 * 60 * 1000);

// ─── HELPER: obter IP real do cliente ─────────────────────────────────────────
function getIP(socket) {
    let ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    return ip;
}

// ─── HELPER: sanitizar e validar tags ─────────────────────────────────────────
function sanitizeTags(raw) {
    if (!Array.isArray(raw)) return [];
    return raw
        .map(t => String(t).trim().toLowerCase().replace(/[^a-záàâãéèêíïóôõöúçñ0-9 _-]/gi, ''))
        .filter(t => t.length > 0 && t.length <= TAG_MAX_LENGTH)
        .slice(0, TAGS_MAX);
}

// ─── EVENTOS DE CONEXÃO ────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    const ip = getIP(socket);
    userIPs.set(socket.id, ip);

    // 1. BAN PERMANENTE?
    if (bannedIPs.has(ip)) {
        socket.emit('system_message', 'ACESSO NEGADO: Foste banido permanentemente dos nossos servidores por múltiplas violações dos Termos de Serviço.');
        socket.disconnect();
        return;
    }

    // 2. LIMITE DE CONEXÕES SIMULTÂNEAS POR IP
    const currentConns = connectionsPerIP.get(ip) || 0;
    if (currentConns >= MAX_CONNECTIONS_PER_IP) {
        socket.emit('system_message', 'Demasiadas conexões do mesmo dispositivo. Fecha outras abas e tenta novamente.');
        socket.disconnect();
        return;
    }
    connectionsPerIP.set(ip, currentConns + 1);

    totalOnlineUsers++;
    io.emit('online_count', totalOnlineUsers);

    // ─── START CHAT ───────────────────────────────────────────────────────────
    socket.on('start_chat', (data) => {
        if (activeRooms.has(socket.id)) return;

        const captchaToken = data?.captchaToken || data;
        const userTags = sanitizeTags(data?.tags);

        // IP MARCADO COMO SPAM? Exige captcha.
        if (flaggedIPs.has(ip)) {
            if (!captchaToken || typeof captchaToken !== 'string') {
                socket.emit('captcha_required');
                return;
            }

            // Chave secreta via variável de ambiente (NUNCA hardcoded em produção!)
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

    // ─── MATCHMAKING ──────────────────────────────────────────────────────────
    function executeMatchmaking(socket, tags) {
        let matchIndex = -1;
        let commonTags = [];

        // Tentativa 1: alguém com tags em comum
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

        // Tentativa 2: qualquer pessoa disponível (fallback aleatório)
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

    // ─── TYPING ───────────────────────────────────────────────────────────────
    socket.on('typing', (isTyping) => {
        const room = activeRooms.get(socket.id);
        if (room) {
            // Valida que é boolean para não mandar lixo ao parceiro
            socket.to(room).emit('stranger_typing', !!isTyping);
        }
    });

    // ─── ENVIO DE MENSAGEM ────────────────────────────────────────────────────
    socket.on('send_message', (msg) => {
        const room = activeRooms.get(socket.id);
        if (!room) return;

        // Validação de tipo e tamanho
        if (typeof msg !== 'string') return;
        const trimmed = msg.trim();
        if (trimmed.length === 0 || trimmed.length > MSG_MAX_LENGTH) return;

        // Detecção de spam (100 msgs idênticas em sequência)
        const currentIp = userIPs.get(socket.id);
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

    // ─── PARAR CHAT ───────────────────────────────────────────────────────────
    socket.on('stop_chat', () => handleDisconnect(socket));

    // ─── REPORTAR UTILIZADOR ─────────────────────────────────────────────────
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

    // ─── DESCONEXÃO ───────────────────────────────────────────────────────────
    socket.on('disconnect', () => {
        totalOnlineUsers = Math.max(0, totalOnlineUsers - 1);
        io.emit('online_count', totalOnlineUsers);

        // Decrementa o contador de conexões do IP
        const connCount = (connectionsPerIP.get(ip) || 1) - 1;
        if (connCount <= 0) {
            connectionsPerIP.delete(ip);
        } else {
            connectionsPerIP.set(ip, connCount);
        }

        userLastMessage.delete(socket.id);
        userIPs.delete(socket.id);
        handleDisconnect(socket);
    });

    // ─── HELPER: limpar sala ─────────────────────────────────────────────────
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

// ─── INICIAR SERVIDOR ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor a correr na porta ${PORT}`);
});
