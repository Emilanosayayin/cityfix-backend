<?php
/**
 * config.php — Configuración de CityFix (variables de entorno o archivo .env)
 */
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0 || strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        $_ENV[trim($k)] = trim($v);
        putenv(trim($k) . '=' . trim($v));
    }
}

function env(string $key, $default = null) {
    $v = $_ENV[$key] ?? getenv($key);
    return ($v === false || $v === null || $v === '') ? $default : $v;
}

define('APP_ENV',  env('APP_ENV', 'local'));
define('APP_NAME', env('APP_NAME', 'CityFix'));

define('DB_HOST',    env('DB_HOST', 'localhost'));
define('DB_USER',    env('DB_USER', 'root'));
define('DB_PASS',    env('DB_PASS', ''));
define('DB_NAME',    env('DB_NAME', 'cityfix_db'));
define('DB_CHARSET', 'utf8mb4');

// En producción el secreto JWT es obligatorio y debe ser largo.
$jwtSecret = env('JWT_SECRET', APP_ENV === 'production' ? '' : 'dev-only-secret-change-me');
if (APP_ENV === 'production' && strlen($jwtSecret) < 32) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => 'Configuración del servidor incompleta']);
    exit;
}
define('JWT_SECRET',         $jwtSecret);
define('JWT_EXPIRY',         (int) env('JWT_EXPIRY', 900));
define('JWT_REFRESH_EXPIRY', (int) env('JWT_REFRESH_EXPIRY', 604800));

define('MAX_LOGIN_ATTEMPTS', (int) env('MAX_LOGIN_ATTEMPTS', 5));
define('LOCKOUT_MINUTES',    (int) env('LOCKOUT_MINUTES', 15));
// Cloudinary (las llaves viven solo en el servidor; la app recibe firmas temporales)
define('CLOUDINARY_CLOUD_NAME', env('CLOUDINARY_CLOUD_NAME', ''));
define('CLOUDINARY_API_KEY',    env('CLOUDINARY_API_KEY', ''));
define('CLOUDINARY_API_SECRET', env('CLOUDINARY_API_SECRET', ''));
define('CLOUDINARY_FOLDER',     env('CLOUDINARY_FOLDER', 'cityfix'));
define('TRUST_PROXY',        env('TRUST_PROXY', '0') === '1');

if (APP_ENV === 'production') {
    error_reporting(0); ini_set('display_errors', '0');
} else {
    error_reporting(E_ALL); ini_set('display_errors', '1');
}
