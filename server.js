const express = require('express');
const http = require('http');
const https = require('https'); 
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));

// Sistemas de Segurança
const bannedIPs = new Set();          // IPs permanentemente banidos (atingiram limite de denúncias)
const flaggedIPs = new Set();         // IPs identificados como Spam/Bots (A partir de agora, pedem Captcha a cada nova conversa)
const reportedIPs = new Map();        // Conta o número de denúncias por IP: IP -> Contagem
const userLastMessage = new Map();    // Guarda a última mensagem de um socket: socket.id -> { text: "...", count: 1 }

const activeRooms = new Map();
const userIPs = new Map();
let waitingQueue = [];
let totalOnlineUsers = 0;

io.on('connection', (socket) => {
    totalOnlineUsers++;
    io.emit('online_count', totalOnlineUsers);

    const ip = socket.handshake.address;
    userIPs.set(socket.id, ip);

    // 1. O IP FOI BANIDO PERMANENTEMENTE?
    if (bannedIPs.has(ip)) {
        socket.emit('system_message', 'ACESSO NEGADO: Você foi banido permanentemente dos nossos servidores por múltiplas violações dos Termos de Serviço.');
        socket.disconnect();
        return;
    }

    socket.on('start_chat', (data) => {
        if (activeRooms.has(socket.id)) return;

        let captchaToken = data?.captchaToken || data;
        let userTags = data?.tags || [];

        // 2. O IP ESTÁ MARCADO COMO SPAM/BOT?
        // Se sim, ele TEM OBRIGATORIAMENTE de fornecer um token do Captcha antes de CADA nova conversa.
        if (flaggedIPs.has(ip)) {
            if (!captchaToken || typeof captchaToken !== 'string') {
                // Diz ao frontend para abrir o modal do Captcha
                socket.emit('captcha_required');
                return;
            }

            // Chave secreta de TESTE oficial do Google
            const secretKey = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'; 
            const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaToken}`;

            // Valida o Captcha no Google
            https.get(url, (res) => {
                let chunkData = '';
                res.on('data', (chunk) => chunkData += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(chunkData);
                        if (result.success) {
                            // Sucesso! Ele é humano. Entra no Matchmaking.
                            // Nota: NÃO removemos ele dos flaggedIPs. Ele terá de fazer o captcha na próxima vez que pular de chat.
                            executeMatchmaking(socket, userTags);
                        } else {
                            socket.emit('system_message', 'Falha na verificação do Captcha. Tente novamente.');
                        }
                    } catch (e) {
                        socket.emit('system_message', 'Erro interno ao validar Captcha.');
                    }
                });
            }).on('error', (err) => {
                socket.emit('system_message', 'Falha na comunicação com o sistema de segurança.');
            });
            
        } else {
            // Usuário normal, não precisa de Captcha!
            executeMatchmaking(socket, userTags);
        }
    });

    function executeMatchmaking(socket, tags) {
        let matchIndex = -1;
        let commonTags = [];

        if (tags && tags.length > 0) {
            matchIndex = waitingQueue.findIndex(u => {
                const intersection = u.tags.filter(t => tags.includes(t));
                if (intersection.length > 0) {
                    commonTags = intersection; 
                    return true;
                }
                return false;
            });
        } else {
            matchIndex = waitingQueue.findIndex(u => !u.tags || u.tags.length === 0);
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
            waitingQueue.push({ socket: socket, tags: tags });
            socket.emit('waiting');
        }
    }

    socket.on('typing', (isTyping) => {
        const room = activeRooms.get(socket.id);
        if (room) {
            socket.to(room).emit('stranger_typing', isTyping);
        }
    });

    // 3. SISTEMA DE DETECÇÃO DE SPAM E BOTS
    socket.on('send_message', (msg) => {
        const room = activeRooms.get(socket.id);
        if (!room) return;

        const currentIp = userIPs.get(socket.id);
        const lastMsgObj = userLastMessage.get(socket.id);

        // Verifica se a mensagem é exata e estritamente igual à anterior
        if (lastMsgObj && lastMsgObj.text === msg) {
            lastMsgObj.count++;
            
            // Se repetiu a MESMA mensagem 100 vezes ou mais (Limite ajustado)
            if (lastMsgObj.count >= 100) {
                flaggedIPs.add(currentIp); // Marca o IP como possível bot
            }
        } else {
            // Nova mensagem diferente, reseta o contador deste usuário
            userLastMessage.set(socket.id, { text: msg, count: 1 });
        }

        // Repassa a mensagem normalmente
        socket.to(room).emit('receive_message', msg);
    });

    socket.on('stop_chat', () => handleDisconnect(socket));

    // 4. SISTEMA DE MODERAÇÃO E DENÚNCIAS
    socket.on('report_user', () => {
        const room = activeRooms.get(socket.id);
        if (room) {
            const clients = io.sockets.adapter.rooms.get(room);
            if (clients) {
                for (const clientId of clients) {
                    if (clientId !== socket.id) {
                        const strangerIP = userIPs.get(clientId);
                        if (strangerIP) {
                            // Adiciona 1 denúncia ao cadastro do IP
                            const currentReports = (reportedIPs.get(strangerIP) || 0) + 1;
                            reportedIPs.set(strangerIP, currentReports);

                            // Se atingiu o limite de 3 denúncias, Bane para sempre
                            if (currentReports >= 3) {
                                bannedIPs.add(strangerIP);
                            }
                        }
                    }
                }
            }
            handleDisconnect(socket);
        }
    });

    socket.on('disconnect', () => {
        totalOnlineUsers--;
        io.emit('online_count', Math.max(0, totalOnlineUsers));
        
        userLastMessage.delete(socket.id); // Limpa o histórico de mensagens
        userIPs.delete(socket.id);
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
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});