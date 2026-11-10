-- CityFix · esquema de autenticación, consentimiento, catálogo y reportes
SET NAMES utf8mb4;
CREATE DATABASE IF NOT EXISTS cityfix_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cityfix_db;

CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    nombre          VARCHAR(100) NOT NULL,
    apellido        VARCHAR(100) NOT NULL,
    email           VARCHAR(150) NOT NULL UNIQUE,
    password        VARCHAR(255) NOT NULL,            -- bcrypt, nunca texto plano
    rol             ENUM('citizen','admin') NOT NULL DEFAULT 'citizen',
    activo          TINYINT(1) NOT NULL DEFAULT 1,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until    DATETIME NULL,
    last_login      DATETIME NULL,
    creado_en       DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Evidencia del consentimiento (LFPDPPP): qué versión del aviso, cuándo y desde qué IP
CREATE TABLE IF NOT EXISTS consentimientos (
    id                      INT AUTO_INCREMENT PRIMARY KEY,
    user_id                 INT NOT NULL,
    version_aviso           VARCHAR(20) NOT NULL,
    finalidades_secundarias TINYINT(1) NOT NULL DEFAULT 0,
    ip                      VARCHAR(45) NOT NULL,
    aceptado_en             DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,           -- SHA-256 del token
    expires_at DATETIME NOT NULL,
    revocado   TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS logs (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NULL,
    ip         VARCHAR(45) NOT NULL,
    accion     VARCHAR(100) NOT NULL,
    resultado  ENUM('ok','denied','error') NOT NULL,
    detalle    VARCHAR(500) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS rate_limits (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    ip          VARCHAR(45) NOT NULL,
    ruta        VARCHAR(100) NOT NULL,
    intentos    INT NOT NULL DEFAULT 1,
    ventana_fin DATETIME NOT NULL,
    UNIQUE KEY unique_ip_ruta (ip, ruta)
) ENGINE=InnoDB;

-- ── Sprint 2: catálogo de categorías y reportes ───────────
CREATE TABLE IF NOT EXISTS categorias (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    nombre      VARCHAR(80) NOT NULL UNIQUE,
    descripcion VARCHAR(255) NULL,
    activo      TINYINT(1) NOT NULL DEFAULT 1,
    creado_en   DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT IGNORE INTO categorias (nombre, descripcion) VALUES
 ('Bache', 'Hundimientos o huecos en la vialidad'),
 ('Alumbrado público', 'Lámparas apagadas o dañadas'),
 ('Fuga de agua', 'Fugas en tomas o tuberías en la vía pública'),
 ('Basura acumulada', 'Tiraderos clandestinos o contenedores desbordados'),
 ('Señalización dañada', 'Semáforos, señales o pintura vial en mal estado'),
 ('Árbol caído o poda', 'Árboles que obstruyen o representan riesgo');

CREATE TABLE IF NOT EXISTS reportes (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT NOT NULL,
    categoria_id INT NOT NULL,
    descripcion  VARCHAR(500) NOT NULL,
    latitud      DOUBLE NOT NULL,
    longitud     DOUBLE NOT NULL,
    direccion    VARCHAR(255) NULL,
    foto_url     VARCHAR(500) NULL,
    estado       ENUM('pendiente','en_proceso','resuelto') NOT NULL DEFAULT 'pendiente',
    creado_en    DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reportes_user (user_id, creado_en),
    FOREIGN KEY (user_id)      REFERENCES users(id)      ON DELETE CASCADE,
    FOREIGN KEY (categoria_id) REFERENCES categorias(id)
) ENGINE=InnoDB;
