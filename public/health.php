<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../src/config.php';
$status = ['app' => APP_NAME, 'status' => 'ok', 'time' => date('c')];
try { require_once __DIR__ . '/../src/db.php'; conectarDB()->query('SELECT 1'); $status['db'] = 'connected'; }
catch (Exception $e) { $status['db'] = 'error'; http_response_code(503); }
echo json_encode($status);
