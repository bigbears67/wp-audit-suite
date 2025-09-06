<?php declare(strict_types=1);
/* ===== Config & helpers communs ===== */
const AUDIT_KEY = 'CHANGE_THIS_PASSWORD'; // <-- mets un mot de passe fort
const MEMORY_LIMIT = '512M';
const TIME_LIMIT   = 240; // 4 min par module
const DEFAULT_MAX  = 1500; // limite résultats par défaut

/* --- Garde d'accès --- */
if (!isset($_GET['key']) || !hash_equals(AUDIT_KEY, (string)$_GET['key'])) {
  http_response_code(403);
  header('Content-Type: text/plain; charset=UTF-8');
  echo "403 Forbidden\n";
  exit;
}

/* --- Bootstrap anti-500 mod_security friendly --- */
@ini_set('display_errors', '0');
@ini_set('log_errors', '1');
@ini_set('memory_limit', MEMORY_LIMIT);
@set_time_limit(TIME_LIMIT);
while (ob_get_level() > 0) { @ob_end_clean(); }
@ini_set('zlib.output_compression','0');
@ini_set('output_buffering','0');
@ini_set('implicit_flush','1');
if (function_exists('header_remove')) { @header_remove('Content-Encoding'); @header_remove('Content-Length'); }
$__LOG = __DIR__ . '/audit_' . basename($_SERVER['SCRIPT_NAME'],'.php') . '_' . date('Ymd') . '.log';
@ini_set('error_log', $__LOG);
register_shutdown_function(function() use ($__LOG){
  $e = error_get_last();
  if ($e && in_array($e['type'], [E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR], true)) {
    @file_put_contents($__LOG, "[FATAL] {$e['message']} in {$e['file']}:{$e['line']}\n", FILE_APPEND);
    if (!headers_sent()) header('Content-Type: text/plain; charset=UTF-8', true, 500);
    echo "Fatal capturée. Voir: {$__LOG}\n";
  }
});

/* --- Contexte WordPress (si présent) --- */
$ROOT = realpath(__DIR__);
$WP_LOADED = false;
if (is_readable($ROOT.'/wp-load.php')) {
  require_once $ROOT.'/wp-load.php';
  $WP_LOADED = true;
}

/* --- Helpers --- */
function esc($s){ return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function shortPath($p){ $p=str_replace('\\','/',$p); $parts=explode('/',$p); $n=count($parts); return $n>4?'.../'.implode('/',array_slice($parts,$n-3)):$p; }
function bytesHuman($b){ $u=['B','KB','MB','GB'];$i=0;while($b>=1024&&$i<count($u)-1){$b/=1024;$i++;}return sprintf('%.2f %s',$b,$u[$i]); }
function safeRead($file,$max=200000){ $sz=@filesize($file)?:0; if($sz<=$max){$c=@file_get_contents($file);return $c?:'';} $h=@fopen($file,'rb'); if(!$h)return''; $buf=@fread($h,$max); @fclose($h); return $buf?:''; }
function listDir($dir){ return is_dir($dir)?array_values(array_diff(scandir($dir),['.','..'])):[]; }
function respond($payload, $format){
  if ($format==='json') {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT);
  } else {
    header('Content-Type: text/plain; charset=UTF-8');
    echo $payload; // déjà text
  }
}
