const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_DATABASE || 'gtim_challenge'
});

// Memoria volátil del servidor para controlar la inactividad 
const activeSessions = new Map();


// RETO ADICIONAL

async function logAudit(req, email, action) {
    try {
        const ipAddress = req.ip || (req.connection && req.connection.remoteAddress) || 'Desconocida';
        const userAgent = req.headers['user-agent'] || 'Desconocido';

        await db.query(
            'INSERT INTO audit_logs (user_email, action_performed, ip_address, user_agent) VALUES (?, ?, ?, ?)',
            [email, action, ipAddress, userAgent]
        );
    } catch (error) {
        // Evita que un fallo en la tabla de auditoría tumbe todo el servidor
        console.error('ALERTA EN AUDITORÍA (No crítica):', error.message);
    }
}

// VERIFICAR INACTIVIDAD 

app.get('/api/verify-session', async (req, res) => {
    const token = req.headers['token'];

    console.log("\n--- [CONSOLA] Verificando sesión activa ---");

    if (!token) {
        return res.status(401).json({ active: false, error: "No hay sesión activa." });
    }

    try {
        const [users] = await db.query('SELECT * FROM users WHERE session_token = ?', [token]);

        if (users.length === 0) {
            console.log("El token no existe en la base de datos.");
            return res.status(401).json({ active: false, error: "Sesión inválida o expirada." });
        }

        const user = users[0];
        
        if (!activeSessions.has(token)) {
            activeSessions.set(token, Date.now());
        }

        const ultimoAccesoMs = activeSessions.get(token);
        const ahoraMs = Date.now();
        
        const segundosInactivo = Math.floor((ahoraMs - ultimoAccesoMs) / 1000);
        const limiteSegundos = 900; //15 minutos

        console.log(`Usuario: ${user.email} | Tiempo inactivo calculado: ${segundosInactivo} segundos.`);

        if (segundosInactivo >= limiteSegundos) {
            console.log("¡INACTIVIDAD DETECTADA! Forzando cierre de sesión...");
            await db.query('UPDATE users SET session_token = NULL WHERE id = ?', [user.id]);
            activeSessions.delete(token); 
            await logAudit(req, user.email, 'CIERRE_SESION_INACTIVIDAD');
            return res.status(401).json({ active: false, error: "Su sesión ha expirado por inactividad (15 minutos)." });
        }

        return res.status(200).json({ active: true, fullName: user.full_name });
    } catch (error) {
        console.error("ERROR EN VERIFICACIÓN:", error);
        return res.status(500).json({ error: "Error interno del servidor." });
    }
});

// REFRESCAR EL RELOJ EN MEMORIA

app.post('/api/update-activity', async (req, res) => {
    const token = req.headers['token'];
    if (!token) return res.sendStatus(401);
    
    activeSessions.set(token, Date.now());
    return res.sendStatus(200);
});

// REGISTRO DE USUARIOS
app.post('/api/signup', async (req, res) => {
    const { email, password, full_name } = req.body;
    try {
        const [existingUser] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ error: "El correo electrónico ya está registrado." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const userId = uuidv4();

        await db.query(
            'INSERT INTO users (id, email, password, full_name) VALUES (?, ?, ?, ?)',
            [userId, email, hashedPassword, full_name]
        );

        await logAudit(req, email, 'REGISTRO');
        return res.status(201).json({ message: "¡Registro exitoso!" });
    } catch (error) {
        console.error("ERROR EN EL ENDPOINT DE REGISTRO:", error);
        return res.status(500).json({ error: "Error interno del servidor." });
    }
});

//  INICIO DE SESIÓN 
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const now = new Date();

        if (users.length === 0) {
            await logAudit(req, email, 'LOGIN_FALLIDO');
            return res.status(401).json({ error: "Credenciales incorrectas." });
        }

        const user = users[0];

        if (user.blocked_until && new Date(user.blocked_until) > now) {
            return res.status(403).json({ error: "Cuenta bloqueada temporalmente por seguridad." });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            const newAttempts = (user.login_attempts || 0) + 1;
            if (newAttempts >= 3) {
                const blockTime = new Date(now.getTime() + 2 * 60 * 60 * 1000);
                await db.query('UPDATE users SET login_attempts = ?, blocked_until = ? WHERE id = ?', [newAttempts, blockTime, user.id]);
                await logAudit(req, email, 'LOGIN_FALLIDO - CUENTA BLOQUEADA');
                return res.status(403).json({ error: "Has alcanzado el límite de 3 intentos. Cuenta bloqueada por 2 horas." });
            } else {
                await db.query('UPDATE users SET login_attempts = ? WHERE id = ?', [newAttempts, user.id]);
                await logAudit(req, email, 'LOGIN_FALLIDO');
                return res.status(401).json({ error: "Credenciales incorrectas." });
            }
        }

        const sessionToken = uuidv4();
        const mysqlHomeString = now.toISOString().slice(0, 19).replace('T', ' ');

        await db.query(
            'UPDATE users SET login_attempts = 0, blocked_until = NULL, session_token = ?, last_activity = ? WHERE id = ?',
            [sessionToken, mysqlHomeString, user.id]
        );

        activeSessions.set(sessionToken, Date.now());
        await logAudit(req, email, 'INICIO_SESION_EXITOSO');

        return res.status(200).json({
            message: `Welcome ${user.full_name}! To logout click here`,
            fullName: user.full_name,
            sessionToken: sessionToken
        });
    } catch (error) {
        console.error("ERROR EN EL ENDPOINT DE LOGIN:", error);
        return res.status(500).json({ error: "Error interno del servidor." });
    }
});

//  CIERRE DE SESIÓN VOLUNTARIO
app.post('/api/logout', async (req, res) => {
    const token = req.headers['token'];
    try {
        const [users] = await db.query('SELECT * FROM users WHERE session_token = ?', [token]);
        if (users.length > 0) {
            await db.query('UPDATE users SET session_token = NULL WHERE id = ?', [users[0].id]);
            activeSessions.delete(token);
            await logAudit(req, users[0].email, 'CIERRE_SESION');
        }
        return res.status(200).json({ message: "Sesión cerrada." });
    } catch (error) {
        console.error("ERROR EN EL ENDPOINT DE LOGOUT:", error);
        return res.status(500).json({ error: "Error al cerrar sesión." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor activo en http://localhost:${PORT}`));
