<?php
/**
 * ReportsController.php — Catálogo de categorías, reportes y firma de subida a Cloudinary
 */
require_once __DIR__ . '/../lib/Security.php';

// ── CATÁLOGO ──────────────────────────────────────────────
function handleCategorias(): void {
    if (!requireMethod('GET')) return;
    requireAuth();
    $rows = conectarDB()->query('SELECT id,nombre,descripcion FROM categorias WHERE activo=1 ORDER BY nombre')->fetchAll();
    foreach ($rows as &$r) $r['id'] = (int)$r['id'];
    jsonOut(['ok' => true, 'categorias' => $rows]);
}

/** Crea o edita (si viene id). Solo admin. */
function handleCategoriaSave(): void {
    if (!requireMethod('POST')) return;
    $p = requireAuth();
    if (!requireAdmin($p)) return;

    $b      = jsonBody();
    $id     = (int)($b['id'] ?? 0);
    $nombre = trim((string)($b['nombre'] ?? ''));
    $desc   = trim((string)($b['descripcion'] ?? ''));
    if ($nombre === '' || mb_strlen($nombre) > 80) { fail('El nombre es obligatorio (máx. 80 caracteres).', 422); return; }
    if (mb_strlen($desc) > 255) { fail('La descripción es demasiado larga (máx. 255).', 422); return; }
    $desc = $desc === '' ? null : $desc;

    $pdo = conectarDB();
    $dup = $pdo->prepare('SELECT id,activo FROM categorias WHERE nombre=? AND id<>?');
    $dup->execute([$nombre, $id]);
    $other = $dup->fetch();

    if ($id > 0) {
        if ($other) { fail('Ya existe una categoría con ese nombre.', 409); return; }
        $pdo->prepare('UPDATE categorias SET nombre=?, descripcion=? WHERE id=? AND activo=1')->execute([$nombre, $desc, $id]);
        logAction((int)$p->id, 'categoria_update', 'ok', "id:$id");
        jsonOut(['ok' => true, 'categoria' => ['id' => $id, 'nombre' => $nombre, 'descripcion' => $desc]]);
        return;
    }

    if ($other) {
        if ((int)$other['activo'] === 1) { fail('Ya existe una categoría con ese nombre.', 409); return; }
        // Reactiva una categoría eliminada antes con el mismo nombre
        $pdo->prepare('UPDATE categorias SET activo=1, descripcion=? WHERE id=?')->execute([$desc, $other['id']]);
        $newId = (int)$other['id'];
    } else {
        $pdo->prepare('INSERT INTO categorias (nombre, descripcion) VALUES (?,?)')->execute([$nombre, $desc]);
        $newId = (int)$pdo->lastInsertId();
    }
    logAction((int)$p->id, 'categoria_create', 'ok', "id:$newId");
    jsonOut(['ok' => true, 'categoria' => ['id' => $newId, 'nombre' => $nombre, 'descripcion' => $desc]], 201);
}

/** Baja lógica (los reportes existentes conservan su categoría). Solo admin. */
function handleCategoriaDelete(): void {
    if (!requireMethod('POST')) return;
    $p = requireAuth();
    if (!requireAdmin($p)) return;
    $id = (int)(jsonBody()['id'] ?? 0);
    if ($id <= 0) { fail('Categoría no válida.', 422); return; }
    conectarDB()->prepare('UPDATE categorias SET activo=0 WHERE id=?')->execute([$id]);
    logAction((int)$p->id, 'categoria_delete', 'ok', "id:$id");
    jsonOut(['ok' => true]);
}

// ── REPORTES ──────────────────────────────────────────────
function handleReportes(): void {
    if (!requireMethod('GET')) return;
    $p = requireAuth();
    $stmt = conectarDB()->prepare(
        'SELECT r.id, r.categoria_id, c.nombre AS categoria, r.descripcion, r.latitud, r.longitud,
                r.direccion, r.foto_url, r.estado, r.creado_en
         FROM reportes r JOIN categorias c ON c.id = r.categoria_id
         WHERE r.user_id = ? ORDER BY r.creado_en DESC, r.id DESC LIMIT 100');
    $stmt->execute([(int)$p->id]);
    jsonOut(['ok' => true, 'reportes' => array_map('reporteOut', $stmt->fetchAll())]);
}

function handleReporteCreate(): void {
    if (!requireMethod('POST')) return;
    $p = requireAuth();
    checkRateLimit(30, 60);

    $b    = jsonBody();
    $cat  = (int)($b['categoria_id'] ?? 0);
    $desc = trim((string)($b['descripcion'] ?? ''));
    $lat  = $b['latitud']  ?? null;
    $lon  = $b['longitud'] ?? null;
    $dir  = trim((string)($b['direccion'] ?? ''));
    $foto = trim((string)($b['foto_url'] ?? ''));

    if ($cat <= 0)                                   { fail('Selecciona una categoría.', 422); return; }
    if (mb_strlen($desc) < 10 || mb_strlen($desc) > 500) { fail('La descripción debe tener entre 10 y 500 caracteres.', 422); return; }
    if (!is_numeric($lat) || !is_numeric($lon) || $lat < -90 || $lat > 90 || $lon < -180 || $lon > 180) {
        fail('Ubicación no válida.', 422); return;
    }
    if (mb_strlen($dir) > 255) $dir = mb_substr($dir, 0, 255);

    // Solo se aceptan fotos alojadas en NUESTRA cuenta de Cloudinary
    if ($foto !== '') {
        $prefix = 'https://res.cloudinary.com/' . CLOUDINARY_CLOUD_NAME . '/';
        if (CLOUDINARY_CLOUD_NAME === '' || strpos($foto, $prefix) !== 0 || strlen($foto) > 500) {
            fail('La URL de la foto no es válida.', 422); return;
        }
    }

    $pdo = conectarDB();
    $c = $pdo->prepare('SELECT id FROM categorias WHERE id=? AND activo=1');
    $c->execute([$cat]);
    if (!$c->fetch()) { fail('La categoría seleccionada no existe.', 422); return; }

    $pdo->prepare('INSERT INTO reportes (user_id,categoria_id,descripcion,latitud,longitud,direccion,foto_url) VALUES(?,?,?,?,?,?,?)')
        ->execute([(int)$p->id, $cat, $desc, (float)$lat, (float)$lon, $dir === '' ? null : $dir, $foto === '' ? null : $foto]);
    $id = (int)$pdo->lastInsertId();
    logAction((int)$p->id, 'reporte_create', 'ok', "id:$id");

    $stmt = $pdo->prepare('SELECT r.id, r.categoria_id, c.nombre AS categoria, r.descripcion, r.latitud, r.longitud,
                                  r.direccion, r.foto_url, r.estado, r.creado_en
                           FROM reportes r JOIN categorias c ON c.id=r.categoria_id WHERE r.id=?');
    $stmt->execute([$id]);
    jsonOut(['ok' => true, 'reporte' => reporteOut($stmt->fetch())], 201);
}

function reporteOut(array $r): array {
    return [
        'id' => (int)$r['id'], 'categoria_id' => (int)$r['categoria_id'], 'categoria' => $r['categoria'],
        'descripcion' => $r['descripcion'], 'latitud' => (float)$r['latitud'], 'longitud' => (float)$r['longitud'],
        'direccion' => $r['direccion'], 'foto_url' => $r['foto_url'], 'estado' => $r['estado'], 'creado_en' => $r['creado_en'],
    ];
}

// ── CLOUDINARY: firma de subida (el API secret nunca sale del servidor) ──
function handleUploadSignature(): void {
    $p = requireAuth();
    checkRateLimit(20, 60);
    if (CLOUDINARY_CLOUD_NAME === '' || CLOUDINARY_API_KEY === '' || CLOUDINARY_API_SECRET === '') {
        fail('Cloudinary no está configurado en el servidor.', 503); return;
    }
    $ts     = time();
    $folder = CLOUDINARY_FOLDER;
    // Cloudinary firma los parámetros ordenados alfabéticamente + el API secret (SHA-1)
    $sig = sha1("folder=$folder&timestamp=$ts" . CLOUDINARY_API_SECRET);
    logAction((int)$p->id, 'upload_signature', 'ok', '');
    jsonOut(['ok' => true, 'cloud_name' => CLOUDINARY_CLOUD_NAME, 'api_key' => CLOUDINARY_API_KEY,
             'timestamp' => $ts, 'folder' => $folder, 'signature' => $sig]);
}
