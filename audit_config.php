<?php declare(strict_types=1);

/**
 * WP Audit Suite — Configuration locale
 *
 * Copiez audit_config.sample.php pour créer ce fichier,
 * puis adaptez vos valeurs. NE PAS pousser ce fichier sur GitHub.
 */

const AUDIT_KEY = 'CHANGE_THIS_PASSWORD';   // mot de passe d’accès via ?key=
const DEFAULT_MAX = 1500;                   // limite de lignes par module

// Racine docroot (détectée automatiquement si vide)
$ROOT = realpath(__DIR__);

// Détection WordPress (lecture seule)
$WP_LOADED = false;
if (file_exists(__DIR__.'/wp-load.php')) {
  require_once __DIR__.'/wp-load.php';
  $WP_LOADED = true;
}

/* --- Helpers communs (lecture seule) --- */
function esc(string $s): string { return htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function bytesHuman(int $n): string { $u=['B','KB','MB','GB','TB']; $i=0; $f=(float)$n; while($f>=1024 && $i<count($u)-1){ $f/=1024; $i++; } return rtrim(rtrim(number_format($f,2,'.',''), '0'),'.').' '.$u[$i]; }
function shortPath(string $p): string { global $ROOT; $p=str_replace('\\','/',$p); $r=str_replace('\\','/',$ROOT); return (strncmp($p,$r,strlen($r))===0) ? ltrim(substr($p,strlen($r)),'/') : $p; }
function respond($payload, string $type='txt', int $code=200): void {
  http_response_code($code);
  if ($type==='json'){ header('Content-Type: application/json; charset=UTF-8'); echo json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT); }
  elseif ($type==='txt'){ header('Content-Type: text/plain; charset=UTF-8'); echo (string)$payload; }
  else{ echo (string)$payload; }
}
function require_auth(): void {
  $key = $_GET['key'] ?? '';
  if (!is_string($key) || $key !== AUDIT_KEY) {
    respond("Unauthorized.\n", 'txt', 401); exit;
  }
}
