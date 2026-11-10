<?php
/**
 * api.php — Punto de entrada de la API de CityFix
 * Uso: POST /api.php?action=register | login | refresh | logout   ·   GET /api.php?action=me
 */
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/db.php';
require_once __DIR__ . '/../src/lib/Security.php';
require_once __DIR__ . '/../src/controllers/AuthController.php';
require_once __DIR__ . '/../src/controllers/ReportsController.php';

sendSecurityHeaders();

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') { http_response_code(204); exit; }

match ($_GET['action'] ?? '') {
    'register' => handleRegister(),
    'login'    => handleLogin(),
    'refresh'  => handleRefresh(),
    'logout'   => handleLogout(),
    'me'       => handleMe(),
    'categorias'       => handleCategorias(),
    'categoria_save'   => handleCategoriaSave(),
    'categoria_delete' => handleCategoriaDelete(),
    'reportes'         => handleReportes(),
    'reporte_create'   => handleReporteCreate(),
    'upload_signature' => handleUploadSignature(),
    default    => fail('Acción no encontrada', 404),
};
