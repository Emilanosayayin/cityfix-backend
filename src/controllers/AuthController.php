<?php
/**
 * AuthController.php — Registro (con consentimiento), login, refresh, logout, me
 * Respuestas JSON: { ok: bool, ... }
 */
require_once __DIR__ . '/../lib/Security.php';

// ── REGISTRO ──────────────────────────────────────────────
function handleRegister(): void {
    if (!requireMethod('POST')) return;
    checkRateLimit(5, 300);

    $b        = jsonBody();
    $nombre   = trim((string)($b['nombre']   ?? ''));
    $apellido = trim((string)($b['apellido'] ?? ''));
    $email    = strtolower(trim((string)($b['email'] ?? '')));
    $password = (string)($b['password'] ?? '');
    $consent  = is_array($b['consentimiento'] ?? null) ? $b['consentimiento'] : [];

    if ($nombre === '' || $apellido === '' || $email === '' || $password === '') {
        fail('Todos los campos son obligatorios.', 422); return;
    }
    if (mb_strlen($nombre) > 100 || mb_strlen($apellido) > 100 || strlen($email) > 150) {
        fail('Alguno de los datos excede la longitud permitida.', 422); return;
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $nombre . $apellido)) {
        fail('El nombre contiene caracteres no válidos.', 422); return;
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { fail('Correo electrónico no válido.', 422); return; }

    $pwError = validatePassword($password);
    if ($pwError) { fail($pwError, 422); return; }

    // Consentimiento explícito: sin aceptar el Aviso de Privacidad no hay cuenta.
    if (($consent['aviso_aceptado'] ?? false) !== true) {
        fail('Debes aceptar el Aviso de Privacidad para crear tu cuenta.', 422); return;
    }
    $version      = substr(trim((string)($consent['version'] ?? '')), 0, 20);
    $secundarias  = (($consent['finalidades_secundarias'] ?? false) === true) ? 1 : 0;
    if ($version === '') { fail('Falta la versión del Aviso de Privacidad.', 422); return; }

    $pdo = conectarDB();
    $check = $pdo->prepare('SELECT id FROM users WHERE email=?');
    $check->execute([$email]);
    if ($check->fetch()) { fail('Este correo ya está registrado.', 409); return; }

    $hash = password_hash($password, PASSWORD_BCRYPT);
    try {
        $pdo->beginTransaction();
        $pdo->prepare('INSERT INTO users (nombre,apellido,email,password) VALUES(?,?,?,?)')
            ->execute([$nombre, $apellido, $email, $hash]);
        $userId = (int)$pdo->lastInsertId();
        $pdo->prepare('INSERT INTO consentimientos (user_id,version_aviso,finalidades_secundarias,ip) VALUES(?,?,?,?)')
            ->execute([$userId, $version, $secundarias, clientIp()]);
        $pdo->commit();
    } catch (Exception $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log('[Register] ' . $e->getMessage());
        fail('No se pudo crear la cuenta. Intenta de nuevo.', 500); return;
    }

    logAction($userId, 'register', 'ok', "aviso:$version");
    jsonOut(['ok' => true, 'message' => 'Cuenta creada correctamente. Ya puedes iniciar sesión.'], 201);
}

// ── LOGIN ─────────────────────────────────────────────────
function handleLogin(): void {
    if (!requireMethod('POST')) return;
    checkRateLimit(10, 60);

    $b        = jsonBody();
    $email    = strtolower(trim((string)($b['email'] ?? '')));
    $password = (string)($b['password'] ?? '');
    if ($email === '' || $password === '') { fail('Correo y contraseña son obligatorios.', 422); return; }

    $pdo  = conectarDB();
    $stmt = $pdo->prepare('SELECT id,nombre,apellido,email,password,rol,activo,failed_attempts,locked_until FROM users WHERE email=?');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
        $min = (int)ceil((strtotime($user['locked_until']) - time()) / 60);
        logAction((int)$user['id'], 'login', 'denied', 'cuenta bloqueada');
        fail("Cuenta bloqueada temporalmente. Intenta en $min minuto(s).", 423); return;
    }

    if (!$user || !password_verify($password, $user['password'])) {
        if ($user) {
            $n    = (int)$user['failed_attempts'] + 1;
            $lock = ($n >= MAX_LOGIN_ATTEMPTS) ? date('Y-m-d H:i:s', time() + LOCKOUT_MINUTES * 60) : null;
            $pdo->prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?')
                ->execute([$lock ? 0 : $n, $lock, $user['id']]);
        }
        logAction($user ? (int)$user['id'] : null, 'login', 'denied', 'credenciales inválidas');
        fail('Correo o contraseña incorrectos.', 401); return;
    }
    if (!(int)$user['activo']) { fail('Cuenta deshabilitada.', 403); return; }

    $pdo->prepare('UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=NOW() WHERE id=?')->execute([$user['id']]);
    issueTokens($user);
}

// ── REFRESH (rotación del refresh token) ──────────────────
function handleRefresh(): void {
    if (!requireMethod('POST')) return;
    checkRateLimit(30, 60);

    $refresh = (string)(jsonBody()['refresh_token'] ?? '');
    if ($refresh === '') { fail('Refresh token requerido.', 422); return; }

    $pdo  = conectarDB();
    $hash = hash('sha256', $refresh);
    $stmt = $pdo->prepare('SELECT rt.id, rt.user_id, rt.revocado, rt.expires_at > NOW() AS vigente,
                                  u.nombre,u.apellido,u.email,u.rol,u.activo
                           FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
                           WHERE rt.token_hash=?');
    $stmt->execute([$hash]);
    $row = $stmt->fetch();

    if (!$row) { fail('Sesión inválida.', 401); return; }

    // Reutilización de un token ya rotado: posible robo → se cierran todas las sesiones.
    if ((int)$row['revocado'] === 1) {
        $pdo->prepare('UPDATE refresh_tokens SET revocado=1 WHERE user_id=?')->execute([$row['user_id']]);
        logAction((int)$row['user_id'], 'refresh', 'denied', 'reuso de refresh token');
        fail('Sesión inválida. Inicia sesión de nuevo.', 401); return;
    }
    if (!(int)$row['vigente'] || !(int)$row['activo']) { fail('Sesión expirada.', 401); return; }

    $pdo->prepare('UPDATE refresh_tokens SET revocado=1 WHERE id=?')->execute([$row['id']]);
    issueTokens([
        'id' => $row['user_id'], 'nombre' => $row['nombre'], 'apellido' => $row['apellido'],
        'email' => $row['email'], 'rol' => $row['rol'],
    ]);
}

// ── LOGOUT ────────────────────────────────────────────────
function handleLogout(): void {
    if (!requireMethod('POST')) return;
    $refresh = (string)(jsonBody()['refresh_token'] ?? '');
    if ($refresh !== '') {
        conectarDB()->prepare('UPDATE refresh_tokens SET revocado=1 WHERE token_hash=?')->execute([hash('sha256', $refresh)]);
    }
    jsonOut(['ok' => true, 'message' => 'Sesión cerrada.']);
}

// ── ME (ruta protegida de ejemplo) ────────────────────────
function handleMe(): void {
    $p = requireAuth();
    jsonOut(['ok' => true, 'user' => [
        'id' => $p->id, 'nombre' => $p->nombre, 'apellido' => $p->apellido, 'email' => $p->email, 'role' => $p->role,
    ]]);
}

// ── HELPERS ───────────────────────────────────────────────
function issueTokens(array $user): void {
    $pdo     = conectarDB();
    $access  = JWT::generar([
        'id' => (int)$user['id'], 'email' => $user['email'], 'nombre' => $user['nombre'],
        'apellido' => $user['apellido'], 'role' => $user['rol'],
    ]);
    $refresh = JWT::generarRefresh();
    $pdo->prepare('INSERT INTO refresh_tokens (user_id,token_hash,expires_at) VALUES(?,?,DATE_ADD(NOW(),INTERVAL ? SECOND))')
        ->execute([$user['id'], hash('sha256', $refresh), JWT_REFRESH_EXPIRY]);
    logAction((int)$user['id'], 'login', 'ok', '');
    jsonOut([
        'ok'            => true,
        'token'         => $access,
        'refresh_token' => $refresh,
        'expires_in'    => JWT_EXPIRY,
        'user'          => [
            'id' => (int)$user['id'], 'nombre' => $user['nombre'], 'apellido' => $user['apellido'],
            'email' => $user['email'], 'role' => $user['rol'],
        ],
    ]);
}

/** 6 reglas: ≥8 caracteres, mayúscula, minúscula, símbolo, sin dígitos ni letras consecutivos. */
function validatePassword(string $pw): ?string {
    if (strlen($pw) < 8)                       return 'La contraseña debe tener al menos 8 caracteres.';
    if (strlen($pw) > 72)                      return 'La contraseña no puede exceder 72 caracteres.';
    if (!preg_match('/[A-Z]/', $pw))           return 'La contraseña debe incluir al menos una mayúscula.';
    if (!preg_match('/[a-z]/', $pw))           return 'La contraseña debe incluir al menos una minúscula.';
    if (!preg_match('/[^A-Za-z0-9]/', $pw))    return 'La contraseña debe incluir al menos un carácter especial (@, #, !, $).';
    $lower = strtolower($pw);
    for ($i = 0; $i < strlen($pw) - 1; $i++) {
        if (ctype_digit($pw[$i]) && ctype_digit($pw[$i + 1]) && ord($pw[$i + 1]) - ord($pw[$i]) === 1)
            return 'La contraseña no debe tener números consecutivos (12, 23, 89).';
        if (ctype_alpha($lower[$i]) && ctype_alpha($lower[$i + 1]) && ord($lower[$i + 1]) - ord($lower[$i]) === 1)
            return 'La contraseña no debe tener letras consecutivas (ab, bc, xy).';
    }
    return null;
}
