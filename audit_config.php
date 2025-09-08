<?php declare(strict_types=1);

/**
 * mod_config — audit de configuration web/app (Apache/PHP/WordPress)
 *
 * Scans:
 *  - .htaccess dangereux (activation PHP, directory listing, SetHandler/AddType x-httpd-php, etc.)
 *  - .htaccess dans /uploads : protection contre l'exécution PHP (détection d'absence)
 *  - .user.ini risqués (auto_prepend/append, allow_url_fopen=On, disable_functions vide)
 *  - Fichiers sensibles exposés: .env, wp-config.*.bak, *.sql, php.ini/web.config dans docroot, backups .htaccess.*
 *
 * Params:
 *  - key=...                     (obligatoire)
 *  - base=...                    (ex: wp-content)  [défaut: racine site]
 *  - max=1500                    (plafond lignes)
 *  - format=html|txt|json        (défaut: html)
 *  - path=full|rel|short         (défaut: rel)
 *  - uploads_recommend=1|0       (défaut: 1) signale l'absence de protection dans uploads
 */

$format = strtolower((string)($_GET['format'] ?? 'html')); // html par défaut
$max    = (int)($_GET['max'] ?? DEFAULT_MAX);

// Base à scanner
$baseIn = isset($_GET['base']) ? (string)$_GET['base'] : '';
$BASE   = $ROOT;
if ($baseIn !== '') {
  $cand = $baseIn;
  if ($cand[0] !== '/' && !preg_match('#^[A-Za-z]:\\\\#', $cand)) {
    $cand = rtrim($ROOT, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . ltrim($cand, DIRECTORY_SEPARATOR);
  }
  $rp = @realpath($cand);
  if ($rp && is_dir($rp)) { $BASE = $rp; }
}

// Affichage chemins
$pathMode = strtolower((string)($_GET['path'] ?? 'rel'));
if (!in_array($pathMode, ['full','rel','short'], true)) $pathMode = 'rel';
$pathOut = function(string $p) use ($pathMode, $ROOT): string {
  $p = str_replace('\\','/',$p);
  $root = str_replace('\\','/', $ROOT);
  $rel = (strncmp($p, $root, strlen($root)) === 0) ? ltrim(substr($p, strlen($root)), '/') : $p;
  if ($pathMode === 'full')  return $p;
  if ($pathMode === 'rel')   return $rel;
  $parts = explode('/', $rel);
  $n = count($parts);
  return ($n > 4) ? ('.../' . implode('/', array_slice($parts, $n - 4))) : $rel;
};

$uploadsRecommend = (int)($_GET['uploads_recommend'] ?? 1);

// Déterminer le répertoire uploads réel si WP chargé
$CONTENT  = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ($ROOT . '/wp-content');
$UPLOADS  = $CONTENT . '/uploads';
if ($WP_LOADED && function_exists('wp_get_upload_dir')) {
  $ud = wp_get_upload_dir();
  if (!empty($ud['basedir'])) $UPLOADS = $ud['basedir'];
}

/* =========================
 *  Helpers lecture & règles
 * ========================= */
function readHead(string $file, int $bytes = 65536): string {
  $h = @fopen($file, 'rb'); if (!$h) return '';
  $buf = @fread($h, $bytes) ?: '';
  @fclose($h);
  return $buf;
}

function htaccess_has_php_enable(string $c): bool {
  $c2 = strtolower($c);
  if (strpos($c2, 'php_flag') !== false && strpos($c2, 'engine on') !== false) return true;
  if (strpos($c2, 'php_admin_flag') !== false && strpos($c2, 'engine on') !== false) return true;
  if (preg_match('/\b(add(handler|type)|sethandler)\b.*php/i', $c)) return true; // AddHandler/AddType/SetHandler ... php
  if (preg_match('/addtype\s+application\/x-httpd-(php|php[0-9]+)/i', $c)) return true;
  return false;
}
function htaccess_has_directory_listing(string $c): bool {
  // Options +Indexes (ou Indexes tout court)
  return (bool)preg_match('/^\s*options\s+.*\bindexes\b/im', $c);
}
function htaccess_disables_php(string $c): bool {
  // Exemples de protections typiques dans uploads :
  // - RemoveHandler/AddType/SetHandler none
  // - <FilesMatch "\.(php|phtml)$"> Deny from all </FilesMatch>
  // - <IfModule mod_php7.c> php_flag engine off </IfModule>
  if (preg_match('/removehandler\s+\.php/i', $c)) return true;
  if (preg_match('/sethandler\s+none/i', $c)) return true;
  if (preg_match('/<filesmatch\s+["\'].*\.(php|phtml|phar)["\']\s*>.*(deny\s+from\s+all|require\s+all\s+denied).*<\/filesmatch>/is', $c)) return true;
  if (preg_match('/php_flag\s+engine\s+off/i', $c)) return true;
  return false;
}
function userini_has_danger(string $c): array {
  $ret = [];
  if (preg_match('/^\s*auto_prepend_file\s*=\s*(.+)$/im', $c, $m)) {
    $ret[] = ['CRITIQUE', 'userini_auto_prepend', 'auto_prepend_file='.trim($m[1])];
  }
  if (preg_match('/^\s*auto_append_file\s*=\s*(.+)$/im', $c, $m)) {
    $ret[] = ['CRITIQUE', 'userini_auto_append', 'auto_append_file='.trim($m[1])];
  }
  if (preg_match('/^\s*allow_url_fopen\s*=\s*on\b/im', $c)) {
    $ret[] = ['ALERTE', 'userini_allow_url_fopen', 'allow_url_fopen=On'];
  }
  if (preg_match('/^\s*disable_functions\s*=\s*(?:\s*|\s*none\s*)$/im', $c)) {
    $ret[] = ['INFO', 'userini_disable_functions_empty', 'disable_functions vide'];
  }
  if (preg_match('/^\s*open_basedir\s*=\s*$/im', $c)) {
    $ret[] = ['INFO', 'userini_open_basedir_empty', 'open_basedir vide'];
  }
  return $ret;
}
function looks_sensitive_filename(string $path): ?array {
  $bn = basename($path);
  $l  = strtolower($bn);
  // Exposés souvent sensibles
  if ($l === '.env')                         return ['ALERTE','dot_env','.env présent (risque d’exposition)'];
  if (preg_match('/^wp-config(\.php)?\.(bak|old|save|orig|txt)$/i', $bn)) return ['ALERTE','wpconfig_backup','Backup wp-config.* détecté'];
  if (preg_match('/\.(sql|sqlite|db|zip|tar|gz|7z)$/i', $bn))             return ['INFO',  'archive_db_like', 'Archive/DB potentiellement sensible'];
  if ($l === 'php.ini')                      return ['ALERTE','php_ini_docroot','php.ini dans le docroot'];
  if ($l === 'web.config')                   return ['INFO',  'web_config_iis','web.config (IIS) présent'];
  if (preg_match('/^\.htaccess\.(bak|old|save|orig)$/i', $bn))            return ['ALERTE','htaccess_backup','Backup .htaccess détecté'];
  return null;
}

/* =========================
 *  Collecte
 * ========================= */
$rows = []; // ['severity','type','path','detail','mtime','size']
$scanned = 0;

$head = [
  "# mod_config — audit configuration",
  "Base: " . shortPath($BASE) . " | " . date('Y-m-d H:i:s')
];

if (is_dir($BASE)) {
  $it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($BASE, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
  );
  foreach ($it as $f) {
    /** @var SplFileInfo $f */
    if (!$f->isFile()) continue;

    $path = $f->getPathname();
    $size = @filesize($path);
    $mtime= @filemtime($path);
    $scanned++;

    $bn = $f->getBasename();

    // .htaccess
    if ($bn === '.htaccess') {
      $c = safeRead($path, 131072);
      $inUploads = (strpos(str_replace('\\','/',$path), str_replace('\\','/',$UPLOADS)) === 0);

      // Dangereux : activation PHP
      if (htaccess_has_php_enable($c)) {
        if (count($rows) < $max) $rows[] = [
          'severity'=>'CRITIQUE','type'=>'htaccess_php_enable','path'=>$path,'size'=>$size,'mtime'=>$mtime,
          'detail'=>'Activation PHP via .htaccess (AddHandler/SetHandler/php_flag engine on)'
        ];
      }

      // Directory listing
      if (htaccess_has_directory_listing($c)) {
        if (count($rows) < $max) $rows[] = [
          'severity'=>'ALERTE','type'=>'htaccess_directory_indexes','path'=>$path,'size'=>$size,'mtime'=>$mtime,
          'detail'=>'Options Indexes actif (listing de répertoire)'
        ];
      }

      // Uploads : protection recommandée
      if ($uploadsRecommend && $inUploads) {
        if (!htaccess_disables_php($c)) {
          if (count($rows) < $max) $rows[] = [
            'severity'=>'ALERTE','type'=>'uploads_no_php_protection','path'=>$path,'size'=>$size,'mtime'=>$mtime,
            'detail'=>'Protection PHP manquante/incomplète dans uploads'
          ];
        } else {
          if (count($rows) < $max) $rows[] = [
            'severity'=>'INFO','type'=>'uploads_php_blocked','path'=>$path,'size'=>$size,'mtime'=>$mtime,
            'detail'=>'Protection PHP détectée dans uploads'
          ];
        }
      }

      // WP canonical (informative)
      if (stripos($c, 'RewriteRule . /index.php') !== false && stripos($c, 'RewriteBase') !== false) {
        if (count($rows) < $max) $rows[] = [
          'severity'=>'INFO','type'=>'htaccess_wp_rewrites','path'=>$path,'size'=>$size,'mtime'=>$mtime,
          'detail'=>'Règles WordPress détectées'
        ];
      }
      continue;
    }

    // .user.ini
    if (strtolower($bn) === '.user.ini') {
      $c = safeRead($path, 65536);
      $finds = userini_has_danger($c);
      foreach ($finds as [$sev,$typ,$det]) {
        if (count($rows) < $max) $rows[] = [
          'severity'=>$sev,'type'=>$typ,'path'=>$path,'size'=>$size,'mtime'=>$mtime,'detail'=>$det
        ];
      }
      if (!empty($finds)) continue;
    }

    // Fichiers sensibles / backups exposés
    if ($sig = looks_sensitive_filename($path)) {
      [$sev,$typ,$det] = $sig;
      if (count($rows) < $max) $rows[] = [
        'severity'=>$sev,'type'=>$typ,'path'=>$path,'size'=>$size,'mtime'=>$mtime,'detail'=>$det
      ];
      continue;
    }
  }
}

/* =========================
 *  Sorties JSON / TXT
 * ========================= */
if ($format === 'json') {
  respond([
    'module'  => 'mod_config',
    'root'    => $ROOT,
    'base'    => $BASE,
    'uploads' => $UPLOADS,
    'time'    => date('c'),
    'scanned' => $scanned,
    'count'   => count($rows),
    'rows'    => $rows,
  ], 'json'); exit;
}

if ($format === 'txt') {
  $out = $head;
  foreach ($rows as $r) {
    $out[] = sprintf('%s\t%s\t%s\t%s\t%s\t%s',
      $r['severity'],
      $r['type'],
      $pathOut($r['path']),
      $r['size']!==false && $r['size']!==null ? bytesHuman((int)$r['size']) : '—',
      $r['mtime'] ? date('Y-m-d H:i:s', (int)$r['mtime']) : '—',
      $r['detail'] ?? ''
    );
  }
  respond(implode("\n", $out)."\n", 'txt'); exit;
}

/* =========================
 *  HTML esthétique
 * ========================= */
header('Content-Type: text/html; charset=UTF-8');

$tot = count($rows);
$crit=$al=$info=0;
foreach ($rows as $r){
  if ($r['severity']==='CRITIQUE') $crit++;
  elseif ($r['severity']==='ALERTE') $al++;
  elseif ($r['severity']==='INFO') $info++;
}
// Types pour filtre
$types = [];
foreach ($rows as $r) { $types[$r['type']] = true; }
ksort($types);
?>
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mod_config — Audit configuration</title>
<style>
:root{--bg:#0f172a;--card:#111827;--muted:#94a3b8;--b:#1f2937;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--info:#60a5fa}
*{box-sizing:border-box}
body{background:var(--bg);color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:0;padding:24px}
h1{margin:0 0 12px}
small{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--b);border-radius:12px;padding:16px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.kpi{background:#0b1220;border:1px solid var(--b);border-radius:10px;padding:12px;text-align:center}
.kpi .v{font-size:20px;font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid}
.badge-ok{color:var(--ok);border-color:var(--ok)}
.badge-warn{color:var(--warn);border-color:var(--warn)}
.badge-bad{color:var(--bad);border-color:var(--bad)}
.badge-info{color:var(--info);border-color:var(--info)}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid var(--b);vertical-align:top}
th{background:#0b1220;text-align:left}
td.path{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
input[type="search"], select{background:#0b1220;border:1px solid var(--b);border-radius:8px;padding:8px;color:#e2e8f0}
.note{color:var(--muted);font-size:12px}
.nowrap{white-space:nowrap}
</style>
</head>
<body>

<h1>mod_config <small>— audit configuration</small></h1>
<div style="margin-bottom: 16px;">
  <button onclick="history.back()" style="background: #0b1220; border: 1px solid #1f2937; border-radius: 10px; padding: 10px 14px; color: #e2e8f0; font-family: inherit; font-size: 14px; cursor: pointer;">
    &larr; Précédent
  </button>
</div>
<div class="card">
  <div class="grid">
    <div class="kpi"><div class="v"><?=esc((string)$scanned)?></div><div>Fichiers scannés</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$tot)?></div><div>Détections</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$crit)?></div><div class="badge badge-bad">Critiques</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$al)?></div><div class="badge badge-warn">Alertes</div></div>
  </div>
  <div class="controls">
    <input id="q" type="search" placeholder="Filtrer chemin/détail…">
    <select id="lvl">
      <option value="">Tous niveaux</option>
      <option value="CRITIQUE">CRITIQUE</option>
      <option value="ALERTE">ALERTE</option>
      <option value="INFO">INFO</option>
    </select>
    <select id="typ">
      <option value="">Tous types</option>
      <?php foreach(array_keys($types) as $t): ?>
        <option value="<?=esc($t)?>"><?=esc($t)?></option>
      <?php endforeach; ?>
    </select>
    <span class="note">
      Base: <?=esc($pathOut($BASE))?> — Uploads: <?=esc($pathOut($UPLOADS))?> — <?=esc(date('Y-m-d H:i:s'))?>
      — <span class="nowrap">max=<?=esc((string)$max)?></span>
    </span>
  </div>
</div>

<div class="card">
  <table id="tbl">
    <thead>
      <tr>
        <th>Niveau</th>
        <th>Type</th>
        <th>Chemin</th>
        <th>Taille</th>
        <th>Modif.</th>
        <th>Détail</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $r):
      $lvl = $r['severity'];
      $cls = $lvl==='CRITIQUE'?'badge-bad':($lvl==='ALERTE'?'badge-warn':'badge-info');
      $sz  = ($r['size']!==false && $r['size']!==null) ? bytesHuman((int)$r['size']) : '—';
      $mt  = $r['mtime'] ? date('Y-m-d H:i:s', (int)$r['mtime']) : '—';
      $pth = $pathOut($r['path']);
    ?>
      <tr>
        <td><span class="badge <?=$cls?>"><?=esc($lvl)?></span></td>
        <td><?=esc($r['type'])?></td>
        <td class="path" title="<?=esc($r['path'])?>"><?=esc($pth)?></td>
        <td><?=esc($sz)?></td>
        <td><?=esc($mt)?></td>
        <td><?=esc($r['detail'] ?? '')?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card">
  <a href="?<?=htmlspecialchars(http_build_query(array_merge($_GET, ['format'=>'json'])), ENT_QUOTES)?>">Exporter JSON</a>
  &nbsp;|&nbsp;
  <a href="?<?=htmlspecialchars(http_build_query(array_merge($_GET, ['format'=>'txt'])), ENT_QUOTES)?>">Exporter texte</a>
  <span class="note"> — Options : <code>&path=full|rel|short</code>, <code>&uploads_recommend=1|0</code>, <code>&base=...</code>.</span>
</div>

<script>
// Filtres client
const q   = document.getElementById('q');
const lvl = document.getElementById('lvl');
const typ = document.getElementById('typ');
const rows = Array.from(document.querySelectorAll('#tbl tbody tr'));

function applyFilter(){
  const needle = q.value.toLowerCase();
  const level  = lvl.value;
  const type   = typ.value;
  rows.forEach(tr => {
    const lvlCell = tr.querySelector('.badge')?.textContent.trim() || '';
    const typeCell= tr.children[1]?.textContent.trim() || '';
    const allTxt  = tr.innerText.toLowerCase();
    const okTxt = !needle || allTxt.includes(needle);
    const okLvl = !level  || lvlCell === level;
    const okTyp = !type   || typeCell === type;
    tr.style.display = (okTxt && okLvl && okTyp) ? '' : 'none';
  });
}
[q,lvl,typ].forEach(el => el.addEventListener('input', applyFilter));
lvl.addEventListener('change', applyFilter);
typ.addEventListener('change', applyFilter);
</script>

</body>
</html>
