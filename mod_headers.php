<?php declare(strict_types=1);
require __DIR__ . '/audit_config.php';

$format = strtolower((string)($_GET['format'] ?? 'html')); // html par défaut
$max    = (int)($_GET['max'] ?? DEFAULT_MAX);

$CONTENT = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ($ROOT . '/wp-content');
$THEMES  = $CONTENT . '/themes';
$PLUGINS = $CONTENT . '/plugins';
$MU      = $CONTENT . '/mu-plugins';

/* ---------- Helpers locaux (headers parsing) ---------- */
function parseHeaderBlock($comment){
  $out = [];
  $comment = str_replace("\r\n", "\n", $comment);
  foreach (explode("\n", $comment) as $line){
    $line = trim(preg_replace('/^\s*\*?\s?/', '', $line) ?? '');
    if ($line === '' || $line[0] === '*' || $line[0] === '/') continue;
    if (preg_match('/^([A-Za-z \-]+)\s*:\s*(.+)$/', $line, $m)) {
      $out[trim($m[1])] = trim($m[2]);
    }
  }
  return $out;
}
function extractCssHeaderFields($buf){
  if (preg_match('/\/\*.*?\*\//s', $buf, $m)) return parseHeaderBlock($m[0]);
  return [];
}
function extractPhpHeaderFields($buf){
  $p = strpos($buf, '<?php');
  if ($p === false) return [];
  if (preg_match('/\/\*.*?\*\//s', $buf, $m, 0, $p)) return parseHeaderBlock($m[0]);
  return [];
}

/**
 * Détection assouplie : autorise les préambules légitimes avant le bloc d'entête plugin.
 * On alerte seulement s'il y a du code exécutable avant le premier bloc "/* ... " contenant "Plugin Name:".
*/
function hasCodeBeforeHeader(string $buf): bool {
  $start = strpos($buf, '<?php');
  if ($start === false) return false;

  $win   = substr($buf, $start, 8192); // ~8 Ko de tête
  $len   = strlen($win);
  $i     = 5; // après "<?php"

  // 1) Trouver le vrai header plugin (bloc /* ... */ avec "Plugin Name:")
  $headerPos = null;
  if (preg_match('/\/\*.*?Plugin\s+Name\s*:.*?\*\//is', $win, $m, PREG_OFFSET_CAPTURE)) {
    $headerPos = $m[0][1];
  }
  if ($headerPos === null) return false; // si pas de header détecté ici, on ne juge pas

  // 2) Consommer les préambules autorisés
  $consume = function($regex) use (&$win, &$i, $len) {
    if (preg_match($regex, $win, $m, PREG_OFFSET_CAPTURE, $i)) {
      if ($m[0][1] === $i) { $i += strlen($m[0][0]); return true; }
    }
    return false;
  };
  while ($i < $headerPos) {
    if ($consume('/\G\s+/A')) continue;                         // espaces
    if ($consume('/\G\/\*.*?\*\//As')) continue;                // /* ... */
    if ($consume('/\G\/\/[^\n]*\n?/A')) continue;               // // ...
    if ($consume('/\Gdeclare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;\s*/Ai')) continue;
    if ($consume('/\Gnamespace\s+[A-Za-z_\x80-\xff][A-Za-z0-9_\\\\\x80-\xff]*\s*;\s*/A')) continue;
    if ($consume('/\Guse\s+[A-Za-z_\x80-\xff][A-Za-z0-9_\\\\,\s\x80-\xff]*(?:\s+as\s+[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)?\s*;\s*/A')) continue;
    if ($consume('/\Gif\s*\(\s*!defined\s*\(\s*[\'"](ABSPATH|WPINC)[\'"]\s*\)\s*\)\s*(?:exit|die)\s*\(\s*\)\s*;\s*/Ai')) continue;
    if ($consume('/\Gdefined\s*\(\s*[\'"](ABSPATH|WPINC)[\'"]\s*\)\s*(\|\||or)\s*(?:exit|die)\s*;\s*/Ai')) continue;

    // 3) Si autre chose AVANT header -> check code exécutable
    $slice = substr($win, $i, max(0, $headerPos - $i));
    if (preg_match('/\b(require|include|include_once|require_once|eval|return|echo|print|function|class|trait|interface|new\s+|for(each)?|while|do|if\s*\(|switch\s*\()\b/i', $slice)) {
      return true; // code avant header = suspect
    }
    break;
  }
  return false;
}

/* ---------- Accumulateur structuré ---------- */
$rows = []; // chaque row: ['scope','name','level','message','path' => optional]
$add  = function(string $scope, string $name, string $level, string $message, ?string $path=null) use (&$rows, $max) {
  if (count($rows) >= $max) return;
  $rows[] = compact('scope','name','level','message','path');
};

/* ---------- THÈMES ---------- */
if (is_dir($THEMES)) {
  foreach (listDir($THEMES) as $t){
    $themeDir = $THEMES . '/' . $t;
    if (!is_dir($themeDir)) continue; // ignore fichiers (ex: index.php)
    $style = $themeDir . '/style.css';
    if (!is_readable($style)) { $add('THEME', $t, 'CRITIQUE', 'style.css manquant'); continue; }
    $hdr = extractCssHeaderFields( safeRead($style, 200000) );
    $miss = [];
    foreach (['Theme Name','Version'] as $k) { if (empty($hdr[$k])) $miss[] = $k; }
    if ($miss) {
      $add('THEME', $t, 'ALERTE', 'Header incomplet (manque: '.implode(', ', $miss).')');
    } else {
      $add('THEME', $t, 'OK', 'Header OK ('.($hdr['Theme Name'] ?? '?').' v'.($hdr['Version'] ?? '?').')');
    }
    if (!empty($hdr['Update URI'])) $add('THEME', $t, 'INFO', 'Update URI: '.$hdr['Update URI']);
    if (!empty($hdr['Template']))   $add('THEME', $t, 'INFO', 'Thème enfant de: '.$hdr['Template']);
  }
}

/* ---------- PLUGINS & MU-PLUGINS ---------- */
function selectPluginMainFile(string $baseDir): ?string {
  $entries = listDir($baseDir);

  // 1) racine du plugin
  foreach ($entries as $f){
    if (!preg_match('/\.php$/i', $f)) continue;
    $p = $baseDir . '/' . $f;
    $buf = safeRead($p, 200000);
    if (preg_match('/\/\*.*?Plugin\s+Name\s*:.*?\*\//is', $buf)) return $p;
  }

  // 2) sous-dossiers courants (inc, includes, core, src, classes) — profondeur 1
  foreach ($entries as $d){
    $sub = $baseDir . '/' . $d;
    if (!is_dir($sub)) continue;
    if (!preg_match('/^(inc|includes?|core|src|classes?)$/i', $d)) continue;
    foreach (listDir($sub) as $f2){
      if (!preg_match('/\.php$/i', $f2)) continue;
      $p2  = $sub . '/' . $f2;
      $buf = safeRead($p2, 200000);
      if (preg_match('/\/\*.*?Plugin\s+Name\s*:.*?\*\//is', $buf)) return $p2;
    }
  }

  // 3) fallback minimal : premier .php à la racine
  foreach ($entries as $f){
    if (preg_match('/\.php$/i', $f)) return $baseDir . '/' . $f;
  }
  return null;
}

function auditPluginsDir_pretty(string $dir, string $label, callable $add){
  if (!is_dir($dir)) return;
  foreach (listDir($dir) as $p){
    $base = $dir . '/' . $p;
    if (!is_dir($base)) continue;

    $entry = selectPluginMainFile($base);
    if (!$entry) { $add($label, $p, 'ALERTE', 'Fichier principal avec header introuvable'); continue; }

    $buf = safeRead($entry, 300000);
    $hdr = extractPhpHeaderFields($buf);
    $miss = [];
    foreach (['Plugin Name','Version'] as $k) { if (empty($hdr[$k])) $miss[] = $k; }

    if (hasCodeBeforeHeader($buf)) $add($label, $p, 'CRITIQUE', 'Code exécutable détecté avant le header');
    if ($miss) $add($label, $p, 'ALERTE', 'Header incomplet (manque: '.implode(', ', $miss).')');
    else       $add($label, $p, 'OK', 'Header OK ('.($hdr['Plugin Name'] ?? '?').' v'.($hdr['Version'] ?? '?').')', $entry);

    if (!empty($hdr['Update URI'])) $add($label, $p, 'INFO', 'Update URI: '.$hdr['Update URI']);
  }
}
auditPluginsDir_pretty($PLUGINS,  'PLUGIN',    $add);
auditPluginsDir_pretty($MU,       'MU-PLUGIN', $add);

/* ---------- Sorties ---------- */
if ($format === 'json') {
  respond(['module'=>'mod_headers','root'=>$ROOT,'time'=>date('c'),'count'=>count($rows),'rows'=>$rows], 'json');
  exit;
}
if ($format === 'txt') {
  $lines = [];
  $lines[] = "# mod_headers — en-têtes thèmes/plugins";
  $lines[] = "Racine: ".shortPath($ROOT)." | WP: ".($WP_LOADED ? 'oui' : 'non')." | ".date('Y-m-d H:i:s');
  foreach ($rows as $r){
    $line = sprintf('%s [%s] %s %s%s',
      $r['scope'],
      $r['name'],
      $r['level']==='OK'?'✅':($r['level']==='INFO'?'ℹ':($r['level']==='ALERTE'?'⚠':'❗')),
      $r['message'],
      isset($r['path']) && $r['path'] ? ' — '.shortPath($r['path']) : ''
    );
    $lines[] = $line;
  }
  respond(implode("\n",$lines)."\n", 'txt');
  exit;
}

/* ---------- HTML esthétique (léger) ---------- */
header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mod_headers — Audit en-têtes thèmes/plugins</title>
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
input[type="search"]{background:#0b1220;border:1px solid var(--b);border-radius:8px;padding:8px;color:#e2e8f0;min-width:240px}
.note{color:var(--muted);font-size:12px}
</style>
</head>
<body>
<?php
$tot = count($rows);
$ok = $warn = $bad = $info = 0;
foreach ($rows as $r){
  if ($r['level']==='OK') $ok++;
  elseif ($r['level']==='ALERTE') $warn++;
  elseif ($r['level']==='CRITIQUE') $bad++;
  elseif ($r['level']==='INFO') $info++;
}
?>
<h1>mod_headers <small>— en-têtes thèmes/plugins</small></h1>

<div style="margin-bottom: 16px;">
  <button onclick="history.back()" style="background: #0b1220; border: 1px solid #1f2937; border-radius: 10px; padding: 10px 14px; color: #e2e8f0; font-family: inherit; font-size: 14px; cursor: pointer;">
    &larr; Précédent
  </button>
</div>
<div class="card">
  <div class="grid">
    <div class="kpi"><div class="v"><?=esc((string)$tot)?></div><div>Total</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$ok)?></div><div class="badge badge-ok">OK</div></div>
    <div class="kpi"><div class="v"><?=esc((string)($warn+$bad))?></div><div class="badge badge-bad">Alertes</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$info)?></div><div class="badge badge-info">Infos</div></div>
  </div>
  <div class="controls">
    <input id="q" type="search" placeholder="Filtrer nom / message…">
<select id="lvl">
  <option value="">Tous niveaux</option>
  <option value="OK">OK</option>
  <option value="INFO">INFO</option>
  <option value="ALERTE">ALERTE</option>
  <option value="CRITIQUE">CRITIQUE</option>
</select>
    <span class="note">Racine: <?=esc(shortPath($ROOT))?> — WP: <?= $WP_LOADED ? 'oui' : 'non' ?> — <?=esc(date('Y-m-d H:i:s'))?></span>
  </div>
</div>

<div class="card">
  <table id="tbl">
    <thead>
      <tr>
        <th>Scope</th>
        <th>Nom</th>
        <th>Niveau</th>
        <th>Message</th>
        <th>Chemin</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $r):
      $lvl = $r['level'];
      $cls = $lvl==='OK'?'badge-ok':($lvl==='ALERTE'?'badge-warn':($lvl==='CRITIQUE'?'badge-bad':'badge-info'));
    ?>
      <tr>
        <td><?=esc($r['scope'])?></td>
        <td><?=esc($r['name'])?></td>
        <td><span class="badge <?=$cls?>"><?=esc($lvl)?></span></td>
        <td><?=esc($r['message'])?></td>
        <td class="path"><?= isset($r['path']) && $r['path'] ? esc(shortPath($r['path'])) : '—' ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card">
  <small class="note">Astuce : ajoute <code>?format=json</code> pour l’export ; <code>?max=500</code> pour plafonner. Module lecture seule.</small>
</div>
<div class="card">
  <div class="note">
    🔔 Rappel : WP Audit Suite est un outil d’audit <b>lecture seule</b>. Ne le laissez pas en production :
    <b>supprimez</b> les fichiers une fois l’audit terminé.
  </div>
</div>
<script>
const q   = document.getElementById('q');
const lvl = document.getElementById('lvl');
const rows = Array.from(document.querySelectorAll('#tbl tbody tr'));
function applyFilter(){
  const needle = q.value.toLowerCase();
  const level  = lvl.value;
  rows.forEach(tr => {
    const txt = tr.innerText.toLowerCase();
    const lvlCell = tr.querySelector('.badge')?.textContent.trim() || '';
    const matchTxt = txt.includes(needle);
    const matchLvl = !level || lvlCell === level;
    tr.style.display = (matchTxt && matchLvl) ? '' : 'none';
  });
}
q.addEventListener('input', applyFilter);
lvl.addEventListener('change', applyFilter);
</script>

</body>
</html>
