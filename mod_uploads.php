<?php declare(strict_types=1);
require __DIR__ . '/audit_config.php';

/**
 * mod_uploads — audit du dossier uploads :
 *  - PHP dans uploads (critique)
 *  - Images piégées (<?php dans les 4 Ko de tête)
 *  - SVG dangereux (onload/script/data:)
 *  - Doubles extensions louches
 *  - .htaccess / .user.ini permettant l'exécution PHP
 *  - Fichiers volumineux (INFO)
 *
 * Params:
 *   - key=...                     (obligatoire)
 *   - max=1500                    (plafond de lignes)
 *   - format=html|txt|json        (défaut: html)
 *   - path=full|rel|short         (défaut: rel)
 *   - recent_days=14              (optionnel) remonte ALERTE si modifs récentes
 *   - big_mb=50                   (optionnel) taille au-delà de laquelle on marque INFO:large_file
 */

$format = strtolower((string)($_GET['format'] ?? 'html')); // html par défaut
$max    = (int)($_GET['max'] ?? DEFAULT_MAX);

$pathMode = strtolower((string)($_GET['path'] ?? 'rel'));
if (!in_array($pathMode, ['full','rel','short'], true)) $pathMode = 'rel';

$recentDays = (int)($_GET['recent_days'] ?? 14);
$recentTs   = $recentDays > 0 ? time() - ($recentDays * 86400) : 0;

$bigMB      = (int)($_GET['big_mb'] ?? 50);
$bigBytes   = max(1, $bigMB) * 1024 * 1024;

// Résolution du chemin uploads
$CONTENT = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ($ROOT . '/wp-content');
$UPLOADS = $CONTENT . '/uploads';
if ($WP_LOADED && function_exists('wp_get_upload_dir')) {
  $ud = wp_get_upload_dir();
  if (!empty($ud['basedir'])) $UPLOADS = $ud['basedir'];
}

// ---- Formatteur de chemin (affichage)
$pathOut = function(string $p) use ($pathMode, $ROOT): string {
  $p = str_replace('\\','/',$p);
  $root = str_replace('\\','/', $ROOT);
  $rel = (strncmp($p, $root, strlen($root)) === 0) ? ltrim(substr($p, strlen($root)), '/') : $p;

  if ($pathMode === 'full')  return $p;
  if ($pathMode === 'rel')   return $rel;

  // short
  $parts = explode('/', $rel);
  $n = count($parts);
  return ($n > 4) ? ('.../' . implode('/', array_slice($parts, $n - 4))) : $rel;
};

// ---- Raccourcis & helpers locaux
function isImageExt(string $path): bool {
  return (bool)preg_match('/\.(png|jpe?g|gif|webp|bmp|ico|svg)$/i', $path);
}
function isPhpExt(string $path): bool {
  return (bool)preg_match('/\.(php|phtml|php[0-9]+)$/i', $path);
}
function hasPhpTagInHead(string $file, int $bytes = 4096): bool {
  $h = @fopen($file, 'rb'); if (!$h) return false;
  $buf = @fread($h, $bytes) ?: '';
  @fclose($h);
  return strpos($buf, '<?php') !== false;
}
function readHead(string $file, int $bytes = 4096): string {
  $h = @fopen($file, 'rb'); if (!$h) return '';
  $buf = @fread($h, $bytes) ?: '';
  @fclose($h);
  return $buf;
}
function svgIsDangerous(string $head): bool {
  // détecte <script>, onload=, xlink:href="data:", javascript:, etc.
  $h = strtolower($head);
  if (strpos($h, '<svg') === false) return false;
  if (strpos($h, '<script') !== false) return true;
  if (preg_match('/on\w+\s*=\s*["\']/i', $h)) return true;
  if (preg_match('/xlink:href\s*=\s*["\']data:/i', $h)) return true;
  if (preg_match('/(?:href|src)\s*=\s*["\']\s*javascript:/i', $h)) return true;
  return false;
}
function looksLikeDoubleExt(string $file): bool {
  $bn = basename($file);
  // ex: image.jpg.php, archive.php.jpg, file.png.phar
  return (bool)preg_match('/\.(?:php|phtml|phar)(?:\.[a-z0-9]{1,5})$/i', $bn)
      || (bool)preg_match('/\.(?:jpe?g|png|gif|webp|svg)\.(?:zip|tar|gz|7z|rar)$/i', $bn);
}
function htaccessEnablesPhp(string $content): bool {
  $c = strtolower($content);
  if (strpos($c, 'php_flag') !== false && strpos($c, 'engine on') !== false) return true;
  if (strpos($c, 'php_admin_flag') !== false && strpos($c, 'engine on') !== false) return true;
  if (preg_match('/add(handler|type)\s+.*php/i', $content)) return true; // AddHandler/Type php
  if (preg_match('/sethandler\s+.*php/i', $content)) return true;
  if (preg_match('/addtype\s+application\/x-httpd-(php|php[0-9]+)/i', $content)) return true;
  return false;
}
// Détecte un index.php/index.html "placeholder" (anti-énumération)
function isIndexPlaceholder(string $path, ?int $size, string $headSample): bool {
  $bn = strtolower(basename($path));
  // cibles courantes
  if (!in_array($bn, ['index.php','index.html','index.htm'], true)) return false;

  // taille raisonnable (placeholder)
  if ($size !== null && $size !== false && $size > 2048) return false;

  // contenu "inoffensif" (pas d'appels dangereux dans l'en-tête)
  $h = strtolower($headSample);
  // mots-clés bénins fréquents
  $benign = (
    strpos($h, 'silence is golden') !== false ||
    strpos($h, 'silence_is_golden') !== false ||
    preg_match('/die\s*\(\s*\)|exit\s*\(\s*\)/i', $headSample) || // die(); exit();
    preg_match('/defined\s*\(\s*[\'"](ABSPATH|WPINC)[\'"]\s*\)\s*or\s*(exit|die)/i', $headSample)
  );

  // aucun "sink" dans les 2-4 Ko de tête
  $danger = preg_match('/\b(eval|assert|include|require|include_once|require_once|call_user_func(?:_array)?|system|exec|shell_exec|passthru|proc_open)\s*\(/i', $headSample);

  return ($benign && !$danger);
}

// ---- Collecte
$rows = []; // ['severity','type','path','size','mtime','detail']
$scanned = 0;
$kpi_php = $kpi_imgphp = $kpi_svg = $kpi_dblext = $kpi_ht = $kpi_ini = $kpi_big = 0;

$headLines = [
  "# mod_uploads — audit du dossier uploads",
  "Uploads: " . shortPath($UPLOADS) . " | " . date('Y-m-d H:i:s')
];

// Scan
if (is_dir($UPLOADS)) {
  $it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($UPLOADS, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
  );
  foreach ($it as $f) {
    /** @var SplFileInfo $f */
    if (!$f->isFile()) continue;

    $path = $f->getPathname();
    $size = @filesize($path); $mtime = @filemtime($path);
    $scanned++;

    // .htaccess / .user.ini
    $bn = strtolower($f->getBasename());
    if ($bn === '.htaccess') {
      $c = safeRead($path, 65536);
      if (htaccessEnablesPhp($c)) {
        $kpi_ht++;
        if (count($rows) < $max) $rows[] = [
          'severity' => 'CRITIQUE',
          'type'     => '.htaccess_php',
          'path'     => $path,
          'size'     => $size,
          'mtime'    => $mtime,
          'detail'   => 'Règles permettant l’exécution PHP dans uploads'
        ];
      }
      continue;
    }
    if ($bn === '.user.ini') {
      $c = safeRead($path, 65536);
      if (stripos($c, 'auto_prepend_file') !== false || stripos($c, 'auto_append_file') !== false) {
        $kpi_ini++;
        if (count($rows) < $max) $rows[] = [
          'severity' => 'CRITIQUE',
          'type'     => '.user.ini',
          'path'     => $path,
          'size'     => $size,
          'mtime'    => $mtime,
          'detail'   => 'auto_prepend/append_file détecté'
        ];
      }
      continue;
    }

    // PHP dans uploads -> CRITIQUE
    // PHP dans uploads -> CRITIQUE
// PHP dans uploads : distinguer placeholder index.* vs fichiers actifs
if (isPhpExt($path)) {
  $kpi_php++;
  $head = readHead($path, 4096);

  if (isIndexPlaceholder($path, $size, $head)) {
    // Par défaut : INFO (on peut aussi décider de ne pas lister du tout)
    if (count($rows) < $max) {
      $rows[] = [
        'severity' => 'INFO',
        'type'     => 'placeholder_index',
        'path'     => $path,
        'size'     => $size,
        'mtime'    => $mtime,
        'detail'   => 'index.* de protection (anti-listing)'
      ];
    }
  } else {
    // Vrai PHP dans uploads => CRITIQUE
    $sev = 'CRITIQUE';
    $detail = 'Fichier PHP dans uploads';
    if ($recentTs && $mtime && $mtime >= $recentTs) $detail .= ' (modifié récemment)';
    if (count($rows) < $max) {
      $rows[] = [
        'severity' => $sev,
        'type'     => 'php_in_uploads',
        'path'     => $path,
        'size'     => $size,
        'mtime'    => $mtime,
        'detail'   => $detail
      ];
    }
  }
  continue;
}



    // Images piégées (<?php dans l’en-tête)
    if (isImageExt($path)) {
      $head = readHead($path, 4096);

      // SVG dangereux
      if (preg_match('/\.svg$/i', $path)) {
        if (svgIsDangerous($head)) {
          $kpi_svg++;
          if (count($rows) < $max) $rows[] = [
            'severity' => 'ALERTE',
            'type'     => 'svg_js',
            'path'     => $path,
            'size'     => $size,
            'mtime'    => $mtime,
            'detail'   => 'Balises/attributs actifs détectés (script/onload/data:)'
          ];
        }
      }

      // PHP tag dans image
      if (strpos($head, '<?php') !== false) {
        $kpi_imgphp++;
        if (count($rows) < $max) $rows[] = [
          'severity' => 'CRITIQUE',
          'type'     => 'php_in_image',
          'path'     => $path,
          'size'     => $size,
          'mtime'    => $mtime,
          'detail'   => 'Tag PHP détecté dans l’en-tête du fichier image'
        ];
      }
    }

    // Doubles extensions
    if (looksLikeDoubleExt($path)) {
      $kpi_dblext++;
      $sev = 'ALERTE';
      if (count($rows) < $max) $rows[] = [
        'severity' => $sev,
        'type'     => 'double_extension',
        'path'     => $path,
        'size'     => $size,
        'mtime'    => $mtime,
        'detail'   => 'Nom de fichier à double extension'
      ];
    }

    // Fichiers volumineux (INFO)
    if ($size !== false && $size >= $bigBytes) {
      $kpi_big++;
      if (count($rows) < $max) $rows[] = [
        'severity' => 'INFO',
        'type'     => 'large_file',
        'path'     => $path,
        'size'     => $size,
        'mtime'    => $mtime,
        'detail'   => 'Fichier volumineux (≥ ' . $bigMB . ' MB)'
      ];
    }
  }
}

/* =========================
 *  Sorties JSON / TXT
 * ========================= */
if ($format === 'json') {
  respond([
    'module'   => 'mod_uploads',
    'root'     => $ROOT,
    'uploads'  => $UPLOADS,
    'time'     => date('c'),
    'scanned'  => $scanned,
    'count'    => count($rows),
    'kpi'      => [
      'php_in_uploads' => $kpi_php,
      'php_in_image'   => $kpi_imgphp,
      'svg_js'         => $kpi_svg,
      'double_ext'     => $kpi_dblext,
      '.htaccess_php'  => $kpi_ht,
      '.user.ini'      => $kpi_ini,
      'large_files'    => $kpi_big,
    ],
    'rows'     => $rows,
  ], 'json'); exit;
}

if ($format === 'txt') {
  $out = $headLines;
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
foreach ($rows as $r){ if($r['severity']==='CRITIQUE')$crit++; elseif($r['severity']==='ALERTE')$al++; elseif($r['severity']==='INFO')$info++; }

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
<title>mod_uploads — Audit uploads</title>
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

<h1>mod_uploads <small>— audit du dossier uploads</small></h1>

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
      Uploads: <?=esc($pathOut($UPLOADS))?> — <?=esc(date('Y-m-d H:i:s'))?>
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
  <span class="note"> — Options : <code>&path=full|rel|short</code>, <code>&recent_days=14</code>, <code>&big_mb=50</code>.</span>
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


if ($format==='json') {
  respond(['module'=>'mod_uploads','root'=>$ROOT,'lines'=>$lines], 'json');
} else {
  respond(implode("\n",$lines)."\n", 'txt');
}
