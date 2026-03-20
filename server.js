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
const bannedIPs = new Set();          
const flaggedIPs = new Set();         
const reportedIPs = new Map();        
const userLastMessage = new Map();    

const activeRooms = new Map();
const userIPs = new Map();
let waitingQueue = [];
let totalOnlineUsers = 0;

// SISTEMA DE LIMPEZA DE MEMÓRIA (Essencial para a Nuvem)
// Limpa os IPs reportados a cada 24h para a memória do Render Grátis não estourar
setInterval(() => {
    reportedIPs.clear();
    console.log('🧹 Limpeza diária de memória efetuada.');
}, 24 * 60 * 60 * 1000);

io.on('connection', (socket) => {
    totalOnlineUsers++;
    io.emit('online_count', totalOnlineUsers);

    // CAPTURA O IP REAL (Proteção para quando o site está hospedado no Render)
    let ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    userIPs.set(socket.id, ip);

    // 1. O IP FOI BANIDO PERMANENTEMENTE?
    if (bannedIPs.has(ip)) {
        socket.emit('system_message', 'ACESSO NEGADO: Foste banido permanentemente dos nossos servidores por múltiplas violações dos Termos de Serviço.');
        socket.disconnect();
        return;
    }

    socket.on('start_chat', (data) => {
        if (activeRooms.has(socket.id)) return;

        let captchaToken = data?.captchaToken || data;
        let userTags = data?.tags || [];

        // 2. O IP ESTÁ MARCADO COMO SPAM/BOT?
        if (flaggedIPs.has(ip)) {
            if (!captchaToken || typeof captchaToken !== 'string') {
                socket.emit('captcha_required');
                return;
            }

            const secretKey = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'; 
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
            }).on('error', (err) => {
                socket.emit('system_message', 'Falha na comunicação com o sistema de segurança.');
            });
            
        } else {
            executeMatchmaking(socket, userTags);
        }
    });

    function executeMatchmaking(socket, tags) {
        let matchIndex = -1;
        let commonTags = [];

        // TENTATIVA 1: Procurar alguém com as MESMAS Tags
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
        
        // TENTATIVA 2: Se não houver tags, ou se não achar ninguém parecido, liga com qualquer pessoa disponível!
        if (matchIndex === -1) {
            matchIndex = waitingQueue.findIndex(u => !u.tags || u.tags.length === 0 || u.tags.length > 0);
            commonTags = []; // Limpa as tags em comum porque foi uma ligação aleatória forçada
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

    socket.on('send_message', (msg) => {
        const room = activeRooms.get(socket.id);
        if (!room) return;

        const currentIp = userIPs.get(socket.id);
        const lastMsgObj = userLastMessage.get(socket.id);

        if (lastMsgObj && lastMsgObj.text === msg) {
            lastMsgObj.count++;
            if (lastMsgObj.count >= 100) {
                flaggedIPs.add(currentIp); 
            }
        } else {
            userLastMessage.set(socket.id, { text: msg, count: 1 });
        }

        socket.to(room).emit('receive_message', msg);
    });

    socket.on('stop_chat', () => handleDisconnect(socket));

    socket.on('report_user', () => {
        const room = activeRooms.get(socket.id);
        if (room) {
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
        
        userLastMessage.delete(socket.id); 
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
    console.log(`🚀 Servidor a correr na porta ${PORT}`);
});
