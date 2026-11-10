<?php
/**
 * Security.php — Cabeceras de seguridad, rate limiting, bitácora y helpers JSON
 */
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/JWT.php';

function sendSecurityHeaders(): void {
    // CORS: necesario para la versión web (Chrome). La autenticación usa el header
    // Authorization (no cookies), por lo que permitir cualquier origen no habilita CSRF.
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Max-Age: 600');
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    if (APP_ENV === 'production') header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

function clientIp(): string {
    if (TRUST_PROXY && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function jsonOut(array $data, int $code = 200): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
}

function fail(string $msg, int $code = 400): void {
    jsonOut(['ok' => false, 'error' => $msg], $code);
}

function jsonBody(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '', true);
    return is_array($data) ? $data : [];
}

function requireMethod(string $method): bool {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== $method) { fail('Método no permitido', 405); return false; }
    return true;
}

function checkRateLimit(int $limit = 10, int $window = 60): void {
    $ip   = clientIp();
    $ruta = substr('api?' . ($_GET['action'] ?? ''), 0, 100);
    try {
        $pdo = conectarDB();
        $pdo->prepare('DELETE FROM rate_limits WHERE ventana_fin < NOW()')->execute();
        $stmt = $pdo->prepare('SELECT id, intentos FROM rate_limits WHERE ip=? AND ruta=? AND ventana_fin>NOW()');
        $stmt->execute([$ip, $ruta]);
        $r = $stmt->fetch();
        if ($r) {
            if ($r['intentos'] >= $limit) {
                fail("Demasiadas solicitudes. Intenta de nuevo en $window segundos.", 429);
                exit;
            }
            $pdo->prepare('UPDATE rate_limits SET intentos=intentos+1 WHERE id=?')->execute([$r['id']]);
        } else {
            $pdo->prepare('INSERT INTO rate_limits (ip,ruta,intentos,ventana_fin) VALUES(?,?,1,DATE_ADD(NOW(),INTERVAL ? SECOND))')
                ->execute([$ip, $ruta, $window]);
        }
    } catch (Exception $e) { error_log('[RateLimit] ' . $e->getMessage()); }
}

/** Bitácora de acceso. Nunca guardar contraseñas ni tokens en $detalle. */
function logAction(?int $userId, string $accion, string $resultado, string $detalle = ''): void {
    try {
        conectarDB()->prepare('INSERT INTO logs (user_id,ip,accion,resultado,detalle) VALUES(?,?,?,?,?)')
            ->execute([$userId, clientIp(), $accion, $resultado, substr($detalle, 0, 500)]);
    } catch (Exception $e) { error_log('[Log] ' . $e->getMessage()); }
}

function bearerToken(): ?string {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? (function_exists('apache_request_headers') ? (apache_request_headers()['Authorization'] ?? null) : null);
    return ($h && preg_match('/^Bearer\s+(.+)$/i', $h, $m)) ? $m[1] : null;
}

/** Valida el JWT del header Authorization; responde 401 y termina si no es válido. */
function requireAuth(): object {
    $token = bearerToken();
    if (!$token) { logAction(null, 'auth_check', 'denied', 'Sin token'); fail('Autenticación requerida', 401); exit; }
    try {
        return JWT::verificar($token);
    } catch (Exception $e) {
        logAction(null, 'auth_check', 'denied', $e->getMessage());
        fail('Sesión inválida o expirada', 401);
        exit;
    }
}


/** Confirma en la BD que el usuario autenticado sigue activo y es admin (no confía solo en el token). */
function requireAdmin(object $payload): bool {
    $stmt = conectarDB()->prepare('SELECT rol FROM users WHERE id=? AND activo=1');
    $stmt->execute([(int)$payload->id]);
    $row = $stmt->fetch();
    if (!$row || $row['rol'] !== 'admin') {
        logAction((int)$payload->id, 'admin_check', 'denied', '');
        fail('Solo los administradores pueden realizar esta acción.', 403);
        return false;
    }
    return true;
}
