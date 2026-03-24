const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const helmet = require('helmet');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e5
});

// ─── TRUST PROXY (fix: X-Forwarded-For não pode ser forjado quando atrás do Render/Nginx) ──
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── CONSTANTES ───────────────────────────────────────────────────────────────
const MSG_MAX_LENGTH        = 500;
const MAX_CONNECTIONS_PER_IP = 4;
const SPAM_THRESHOLD        = 100;
const TAGS_MAX              = 10;
const TAG_MAX_LENGTH        = 30;
const MAX_VIOLATIONS        = 3;

// Rate-limit de mensagens
const RATE_LIMIT_MSGS   = 5;
const RATE_LIMIT_WINDOW = 3000;   // ms

// Rate-limit de eventos de controlo (start_chat, stop_chat, report_user)
const CONTROL_COOLDOWN  = 2000;   // ms mínimo entre chamadas ao mesmo evento

// ─── LISTAS DE PALAVRAS PROIBIDAS ─────────────────────────────────────────────
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

// ─── PERSISTÊNCIA DE BANS ─────────────────────────────────────────────────────
// Salva bannedIPs e flaggedIPs em arquivo JSON para sobreviver a reinicializações.
// No Render free tier o disco é efêmero entre deploys, mas persiste entre restarts
// normais (cold starts). Para persistência total entre deploys, use um volume pago
// ou um banco externo — mas isso já resolve 90% dos casos práticos.
const BANS_FILE = path.join(__dirname, 'bans.json');

function loadBans() {
    try {
        if (fs.existsSync(BANS_FILE)) {
            const data = JSON.parse(fs.readFileSync(BANS_FILE, 'utf8'));
            return {
                banned:  new Set(data.banned  || []),
                flagged: new Set(data.flagged || []),
            };
        }
    } catch (e) {
        console.warn('⚠️  Falha ao carregar bans.json, iniciando limpo:', e.message);
    }
    return { banned: new Set(), flagged: new Set() };
}

function saveBans() {
    try {
        fs.writeFileSync(BANS_FILE, JSON.stringify({
            banned:  [...bannedIPs],
            flagged: [...flaggedIPs],
        }), 'utf8');
    } catch (e) {
        console.error('❌ Falha ao salvar bans.json:', e.message);
    }
}

const { banned: bannedIPs, flagged: flaggedIPs } = loadBans();
console.log(`📂 Bans carregados: ${bannedIPs.size} banidos, ${flaggedIPs.size} sinalizados.`);

// ─── ESTADO GLOBAL ────────────────────────────────────────────────────────────
const reportedIPs        = new Map();
const userLastMessage    = new Map();
const activeRooms        = new Map();
const userIPs            = new Map();
const connectionsPerIP   = new Map();
const violacoesUsuario   = new Map();
const messageTimes       = new Map();    // Rate-limit de mensagens
const lastStartTime      = new Map();    // Rate-limit de start_chat
const lastStopTime       = new Map();    // Rate-limit de stop_chat
const hasReported        = new Set();    // Previne report_user em loop

let waitingQueue     = [];
let totalOnlineUsers = 0;

// Limpeza diária de memória
setInterval(() => {
    reportedIPs.clear();
    console.log('🧹 Limpeza diária de memória efetuada.');
}, 24 * 60 * 60 * 1000);

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function getIP(socket) {
    // Com trust proxy = 1, o Express já valida o header corretamente
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

// Controla rate-limit genérico de evento de controlo
// Retorna true se a chamada deve ser bloqueada
function isControlThrottled(map, socketId, cooldown) {
    const now = Date.now();
    const last = map.get(socketId) || 0;
    if (now - last < cooldown) return true;
    map.set(socketId, now);
    return false;
}

// ─── SOCKET.IO ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    const ip = getIP(socket);
    userIPs.set(socket.id, ip);

    // Verificar ban
    if (bannedIPs.has(ip)) {
        socket.emit('system_message', 'ACESSO NEGADO: Foste banido permanentemente dos nossos servidores por múltiplas violações dos Termos de Serviço.');
        socket.disconnect();
        return;
    }

    // Verificar limite de conexões por IP
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

    // ── start_chat ────────────────────────────────────────────────────────────
    socket.on('start_chat', (data) => {
        // FIX: Rate-limit em start_chat
        if (isControlThrottled(lastStartTime, socket.id, CONTROL_COOLDOWN)) return;

        if (activeRooms.has(socket.id)) return;

        const captchaToken = data?.captchaToken || data;
        const userTags     = sanitizeTags(data?.tags);

        if (flaggedIPs.has(ip)) {
            if (!captchaToken || typeof captchaToken !== 'string') {
                socket.emit('captcha_required');
                return;
            }

            const secretKey = process.env.RECAPTCHA_SECRET_KEY;
            if (!secretKey) {
                console.error('❌ RECAPTCHA_SECRET_KEY não configurada! Defina a variável de ambiente no Render.');
                socket.emit('system_message', 'Erro interno de configuração do servidor.');
                return;
            }

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

    // ── Matchmaking ───────────────────────────────────────────────────────────
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
            const partner       = waitingQueue.splice(matchIndex, 1)[0];
            const partnerSocket = partner.socket;
            const roomName      = `room_${partnerSocket.id}_${socket.id}`;

            socket.join(roomName);
            partnerSocket.join(roomName);

            activeRooms.set(socket.id,       roomName);
            activeRooms.set(partnerSocket.id, roomName);

            io.to(socket.id).emit('chat_started',       { commonTags });
            io.to(partnerSocket.id).emit('chat_started', { commonTags });
        } else {
            waitingQueue.push({ socket, tags });
            socket.emit('waiting');
        }
    }

    // ── typing ────────────────────────────────────────────────────────────────
    socket.on('typing', (isTyping) => {
        const room = activeRooms.get(socket.id);
        if (room) socket.to(room).emit('stranger_typing', !!isTyping);
    });

    // ── send_message ──────────────────────────────────────────────────────────
    socket.on('send_message', (msg) => {
        const room = activeRooms.get(socket.id);
        if (!room) return;

        if (typeof msg !== 'string') return;
        const trimmed = msg.trim();
        if (trimmed.length === 0 || trimmed.length > MSG_MAX_LENGTH) return;

        const currentIp = userIPs.get(socket.id);

        // Palavras proibidas
        const { temViolacao, msgCensurada } = verificarMensagem(trimmed);
        if (temViolacao) {
            const violacoes = (violacoesUsuario.get(socket.id) || 0) + 1;
            violacoesUsuario.set(socket.id, violacoes);
            console.log(`⚠️ Violação ${violacoes}/${MAX_VIOLATIONS} - IP: ${currentIp}`);

            if (violacoes >= MAX_VIOLATIONS) {
                bannedIPs.add(currentIp);
                saveBans();
                console.log(`🚫 IP banido por violações repetidas: ${currentIp}`);
                setTimeout(() => { handleDisconnect(socket); socket.disconnect(); }, 2000);
            }

            socket.to(room).emit('receive_message', msgCensurada);
            socket.to(room).emit('system_message', '⚠️ Parte da mensagem foi ocultada por violar as regras da plataforma.');
            return;
        }

        // Rate-limit de velocidade
        const now   = Date.now();
        const times = (messageTimes.get(socket.id) || []).filter(t => now - t < RATE_LIMIT_WINDOW);
        times.push(now);
        messageTimes.set(socket.id, times);
        if (times.length > RATE_LIMIT_MSGS) {
            flaggedIPs.add(currentIp);
            saveBans();
            console.log(`⚡ Rate limit atingido - IP: ${currentIp}`);
            return;
        }

        // Detecção de spam por repetição
        const lastMsgObj = userLastMessage.get(socket.id);
        if (lastMsgObj && lastMsgObj.text === trimmed) {
            lastMsgObj.count++;
            if (lastMsgObj.count >= SPAM_THRESHOLD) { flaggedIPs.add(currentIp); saveBans(); }
        } else {
            userLastMessage.set(socket.id, { text: trimmed, count: 1 });
        }

        socket.to(room).emit('receive_message', trimmed);
    });

    // ── stop_chat ─────────────────────────────────────────────────────────────
    socket.on('stop_chat', () => {
        // FIX: Rate-limit em stop_chat para evitar handleDisconnect em loop
        if (isControlThrottled(lastStopTime, socket.id, CONTROL_COOLDOWN)) return;
        handleDisconnect(socket);
    });

    // ── report_user ───────────────────────────────────────────────────────────
    socket.on('report_user', () => {
        // FIX: Cada socket só pode reportar uma vez por sessão
        if (hasReported.has(socket.id)) return;
        hasReported.add(socket.id);

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
                            saveBans();
                            console.log(`🚫 IP banido por múltiplos reports: ${strangerIP}`);
                        }
                    }
                }
            }
        }
        handleDisconnect(socket);
    });

    // ── disconnect ────────────────────────────────────────────────────────────
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
        lastStartTime.delete(socket.id);
        lastStopTime.delete(socket.id);
        hasReported.delete(socket.id);

        handleDisconnect(socket);
    });

    // ── handleDisconnect (interno) ────────────────────────────────────────────
    function handleDisconnect(sock) {
        // Remove da fila de espera
        waitingQueue = waitingQueue.filter(u => u.socket.id !== sock.id);

        const room = activeRooms.get(sock.id);
        if (room) {
            sock.to(room).emit('stranger_disconnected');
            const clients = io.sockets.adapter.rooms.get(room);
            if (clients) {
                for (const clientId of clients) {
                    activeRooms.delete(clientId);        // FIX: limpa TODOS os membros da sala
                    const clientSocket = io.sockets.sockets.get(clientId);
                    if (clientSocket) clientSocket.leave(room);
                }
            }
            // FIX: garante que o próprio socket também é removido
            activeRooms.delete(sock.id);
        }
    }
});

// ─── PÁGINA 404 PERSONALIZADA ─────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Servidor a correr na porta ${PORT}`);

    // Aviso em desenvolvimento quando a chave real não estiver configurada
    if (!process.env.RECAPTCHA_SECRET_KEY) {
        console.warn('⚠️  RECAPTCHA_SECRET_KEY não definida. Configure a variável de ambiente no Render.');
    }
});
