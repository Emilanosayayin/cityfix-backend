<?php
/**
 * JWT.php — JSON Web Token HS256
 */
require_once __DIR__ . '/../config.php';

class JWT {
    public static function generar(array $payload): string {
        $header = self::b64u(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload['iat'] = time();
        $payload['exp'] = time() + JWT_EXPIRY;
        $pay = self::b64u(json_encode($payload));
        $sig = self::b64u(hash_hmac('sha256', "$header.$pay", JWT_SECRET, true));
        return "$header.$pay.$sig";
    }

    /** Token opaco aleatorio; en la BD solo se guarda su hash SHA-256. */
    public static function generarRefresh(): string {
        return bin2hex(random_bytes(32));
    }

    public static function verificar(string $token): object {
        $p = explode('.', $token);
        if (count($p) !== 3) throw new Exception('Token malformado');
        [$h, $pay, $sig] = $p;

        $head = json_decode(self::b64uDec($h));
        if (!$head || ($head->alg ?? '') !== 'HS256') throw new Exception('Algoritmo no permitido');

        $expected = self::b64u(hash_hmac('sha256', "$h.$pay", JWT_SECRET, true));
        if (!hash_equals($expected, $sig)) throw new Exception('Firma inválida');

        $data = json_decode(self::b64uDec($pay));
        if (!$data) throw new Exception('Payload malformado');
        if (!isset($data->exp) || $data->exp < time()) throw new Exception('Token expirado');
        return $data;
    }

    private static function b64u(string $d): string {
        return rtrim(strtr(base64_encode($d), '+/', '-_'), '=');
    }
    private static function b64uDec(string $d): string {
        $d = strtr($d, '-_', '+/');
        $pad = (4 - strlen($d) % 4) % 4;
        return (string) base64_decode($d . str_repeat('=', $pad));
    }
}
