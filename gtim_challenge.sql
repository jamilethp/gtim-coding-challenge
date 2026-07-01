DROP DATABASE IF EXISTS gtim_challenge;


CREATE DATABASE gtim_challenge;
USE gtim_challenge;

--  TABLA PRINCIPAL: Usuarios 
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY, -- Identificadores únicos 
    email VARCHAR(254) NOT NULL UNIQUE, -- Longitud estricta bajo la norma RFC 5321
    password VARCHAR(255) NOT NULL, -- Contraseñas encriptadas 
    full_name VARCHAR(255) NOT NULL,
    
    -- Control de seguridad para bloqueo de cuentas
    login_attempts INT DEFAULT 0,
    blocked_until DATETIME NULL,
    
    -- Control de persistencia y sesión única
    session_token VARCHAR(255) NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- TABLA DEL RETO ADICIONAL: Sistema de Auditoría
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(254) NOT NULL, -- Correo del usuario 
    action_performed VARCHAR(50) NOT NULL, -- 'REGISTRO', 'INICIO_SESION_EXITOSO', 'LOGIN_FALLIDO', 'CIERRE_SESION'
    log_date DATETIME DEFAULT CURRENT_TIMESTAMP, -- Fecha y hora automática del servidor
    ip_address VARCHAR(45) NULL, -- Direcciones 
    user_agent TEXT NULL -- Navegador y sistema operativo
);