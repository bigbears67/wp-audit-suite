<?php declare(strict_types=1);
require __DIR__ . '/audit_config.php';

/**
 * mod_files — scan fichiers PHP avec contexte (moins de faux positifs)
 * Params:
 *   - key=...                  (obligatoire)
 *   - base=...                 (ex: wp-content/plugins)
 *   - max=1500                 (plafond de lignes)
 *   - format=html|txt|json     (défaut: html)
 */

$format = strtolower((string)($_GET['format'] ?? 'html'));
$max    = (int)($_GET['max'] ?? DEFAULT_MAX);
$baseIn = isset($_GET['base']) ? (string)$_GET['base'] : '';
$base   = $ROOT;
// ---- Format d'affichage des chemins : full | rel | short (défaut: rel)
$pathMode = strtolower((string)($_GET['path'] ?? 'rel'));
if (!in_array($pathMode, ['full','rel','short'], true)) $pathMode = 'rel';

// Formatteur local (closure) pour afficher le chemin selon $pathMode
$pathOut = function(string $p) use ($pathMode, $ROOT): string {
    $p = str_replace('\\','/', $p);
    $root = str_replace('\\','/', $ROOT);

    // construit un chemin relatif si possible
    $rel = (strncmp($p, $root, strlen($root)) === 0) ? ltrim(substr($p, strlen($root)), '/') : $p;

    if ($pathMode === 'full')  return $p;
    if ($pathMode === 'rel')   return $rel;

    // short: les 4 derniers segments max, avec "..."
    $parts = explode('/', $rel);
    $n = count($parts);
    return ($n > 4) ? ('.../' . implode('/', array_slice($parts, $n - 4))) : $rel;
};

// Résolution sûre du répertoire de base
if ($baseIn !== '') {
  $cand = $baseIn;
  if ($cand[0] !== '/' && !preg_match('#^[A-Za-z]:\\\\#', $cand)) {
    $cand = rtrim($ROOT, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . ltrim($cand, DIRECTORY_SEPARATOR);
  }
  $rp = @realpath($cand);
  if ($rp && is_dir($rp)) { $base = $rp; }
}

/* =========================
 *  Heuristiques & helpers
 * ========================= */

// Librairies “connues” -> sévérité abaissée si pas de contexte dangereux
$VENDOR_SAFE = [
  '#/vendor/#i', '#/phpseclib/#i', '#/Monolog/#i', '#/guzzlehttp/#i', '#/google/#i',
  '#/voku/#i', '#/cmb2/#i', '#/Dependencies/Minify/#i', '#/symfony/#i', '#/psr/#i',
];

function is_vendor_safe(string $path, array $rules): bool {
  $p = str_replace('\\','/',$path);
  foreach ($rules as $re) { if (preg_match($re, $p)) return true; }
  return false;
}

// Nettoyer le code: retirer commentaires & chaînes (évite les matches dans du texte)
function strip_comments_strings(string $src): string {
  if (!function_exists('token_get_all')) return $src; // fallback
  $out = '';
  foreach (token_get_all($src) as $tok) {
    if (is_array($tok)) {
      [$id, $text] = $tok;
      if ($id === T_COMMENT || $id === T_DOC_COMMENT || $id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) {
        $out .= str_repeat(' ', strlen($text)); // préserver indexation/longueur
      } else {
        $out .= $text;
      }
    } else {
      $out .= $tok;
    }
  }
  return $out;
}

// Proximité: entrée utilisateur -> fonction dangereuse (fenêtre courte)
// STRICT : user input directement dans les parenthèses d'un appel dangereux
function has_user_input_to_exec_strict(string $buf): bool {
    if (preg_match('/\b(eval|assert|include(?:_once)?|require(?:_once)?|call_user_func(?:_array)?)\s*\((?:(?!\)).)*\$_(?:GET|POST|REQUEST)(?:(?!\)).)*\)/is', $buf)) return true;
    if (preg_match('/\b(system|exec|shell_exec|passthru|proc_open)\s*\((?:(?!\)).)*\$_(?:GET|POST|REQUEST)(?:(?!\)).)*\)/is', $buf)) return true;
    return false;
}
function exec_uses_user_input_but_sanitized(string $buf): bool {
    return (bool)preg_match('/\b(system|exec|shell_exec|passthru)\s*\((?:(?!\)).)*(escapeshellarg|escapeshellcmd)\s*\((?:(?!\)).)*\$_(?:GET|POST|REQUEST)(?:(?!\)).)*(?:(?!\)).)*\)/is', $buf);
}

function has_uploads_include(string $buf): bool {
  return (bool)preg_match('#(include|require)(_once)?\s*\(\s*[\'"][^\'"]*wp-content/uploads/[^\'"]+[\'"]\s*\)#i', $buf);
}

function has_big_base64_payload(string $src, int $threshold = 300): bool {
  if (preg_match_all('/base64_decode\s*\(\s*[\'"]([A-Za-z0-9+\/=]{'.$threshold.',})[\'"]\s*\)/i', $src, $m)) {
    return true;
  }
  return false;
}

// Motifs "simples" (après nettoyage) – tous seront reclassés via le contexte
$patterns = [
  ['eval()',             '/\beval\s*\(/i',                                              'ALERTE'],
  ['assert()',           '/\bassert\s*\(/i',                                            'ALERTE'],
  ['system/exec',        '/\b(system|exec|shell_exec|passthru)\s*\(/i',                'INFO'],   // ↓ par défaut
  ['proc_open',          '/\bproc_open\s*\(/i',                                         'INFO'],   // ↓ par défaut
  ['preg_replace /e',    '/preg_replace\s*\([^)]*\/[imsxADSUXu]*e[imsxADSUXu]*[\'"]\s*\)/i', 'ALERTE'],
  ['base64_decode',      '/\bbase64_decode\s*\(/i',                                     'INFO'],   // ↓ par défaut
  // "variables variables" ne déclenche plus seul : traité par heuristique dédiée
];


/* =========================
 *  Scan d’un fichier
 * ========================= */
function scan_one_file(string $path, array $patterns, array $vendorRules, int $maxInline = 250000): array {
$raw = safeRead($path, $maxInline);
$buf = strip_comments_strings($raw);

$vendor = is_vendor_safe($path, $vendorRules);

$ctx_user_exec_strict = has_user_input_to_exec_strict($buf);
$ctx_user_exec_sanit  = $ctx_user_exec_strict && exec_uses_user_input_but_sanitized($buf);
$ctx_uploads          = has_uploads_include($buf);
$ctx_bigb64           = has_big_base64_payload($raw, 600); // seuil élevé
$ctx_var_near_sink    = has_variables_near_sink($buf);
$ctx_var_from_input   = has_variables_from_superglobal($buf) || has_dynamic_call_from_input($buf);

  $hits = [];
  foreach ($patterns as [$label, $re, $baseSev]) {
    if (!preg_match($re, $buf)) continue;

    $sev = $baseSev;

    // Base64: INFO par défaut, ALERTE si payload long
    if ($label === 'base64_decode') {
        $sev = $ctx_bigb64 ? 'ALERTE' : 'INFO';
    }

    // Uploads => CRITIQUE
    if ($ctx_uploads) {
        $sev = 'CRITIQUE';
    }

    // Chaîne stricte "user input → exec"
    if ($ctx_user_exec_strict) {
        $sev = $ctx_user_exec_sanit ? 'ALERTE' : 'CRITIQUE';
    }

    // system/exec/proc_open sans input => INFO
    if (in_array($label, ['system/exec','proc_open'], true) && !$ctx_user_exec_strict) {
        $sev = 'INFO';
    }

    // Vendors connus : on dégrade si pas de contexte strict/UPLOADS/payload long
    if ($vendor && !$ctx_user_exec_strict && !$ctx_uploads && !$ctx_bigb64) {
        if ($sev === 'CRITIQUE') $sev = 'ALERTE';
        elseif ($sev === 'ALERTE') $sev = 'INFO';
    }

    $hits[$label] = ['severity'=>$sev, 'pattern'=>$label];
}


  // Ajouts contextuels explicites (si détectés)
  if ($ctx_uploads)            { $hits['include_from_uploads'] = ['severity'=>'CRITIQUE','pattern'=>'include_from_uploads']; }
if ($ctx_user_exec_strict)   { $hits['user_input_to_exec']   = ['severity'=>$ctx_user_exec_sanit ? 'ALERTE' : 'CRITIQUE', 'pattern'=>'user_input_to_exec']; }
if ($ctx_bigb64)             { $hits['base64_payload']       = ['severity'=>'ALERTE','pattern'=>'base64_payload']; }


  // Finalisation
  $rows = [];
  foreach ($hits as $h) {
    $rows[] = [
      'severity' => $h['severity'],
      'pattern'  => $h['pattern'],
      'path'     => $path,
      'size'     => (@filesize($path) ?: null),
      'mtime'    => (@filemtime($path) ?: null),
    ];
  }
  return $rows;
}
// Variables variables proches d'un "sink" (eval/include/require/system/exec…)
function has_variables_near_sink(string $buf, int $win = 180): bool {
    $reVar   = '(?:\$\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*|\$\{\$[^}]*\})';
    $reSink  = '(?:eval|assert|include(?:_once)?|require(?:_once)?|call_user_func(?:_array)?|system|exec|shell_exec|passthru|proc_open)';
    return (bool)preg_match('/' . $reVar . '.{0,' . $win . '}\b' . $reSink . '\s*\(/is', $buf);
}

// Variables variables alimentées par un superglobal (même ligne/appel)
function has_variables_from_superglobal(string $buf): bool {
    return (bool)preg_match('/(?:\$\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*|\$\{\$[^}]*\}).{0,200}\$_(?:GET|POST|REQUEST)\b/is', $buf);
}

// Appel dynamique $func($_GET...) ou include($path) avec superglobal
function has_dynamic_call_from_input(string $buf): bool {
    if (preg_match('/\$\s*[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\s*\(\s*(?:(?!\)).)*\$_(?:GET|POST|REQUEST)/is', $buf)) return true;
    if (preg_match('/\binclude(?:_once)?|require(?:_once)?\s*\(\s*\$[^)]*\$_(?:GET|POST|REQUEST)/is', $buf)) return true;
    return false;
}

/* =========================
 *  Collecte
 * ========================= */
$rows = [];
$scanned = 0;
$head = [
  "# mod_files — patterns avec contexte",
  "Base: " . shortPath($base) . " | " . date('Y-m-d H:i:s'),
];

if (is_dir($base)) {
  $it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
  );

  foreach ($it as $f) {
    /** @var SplFileInfo $f */
    if (!$f->isFile()) continue;

    $path = $f->getPathname();
    if (!preg_match('/\.(php|phtml|php7|php8)$/i', $path)) continue;

    $scanned++;

    // >>> Tous les calculs de contexte et les drapeaux se font DANS scan_one_file()
    $hits = scan_one_file($path, $patterns, $VENDOR_SAFE, 250000);

    if (!empty($hits)) {
      foreach ($hits as $h) {
        if (count($rows) >= $max) break 2; // stop propre si on atteint le plafond
        $rows[] = $h;
      }
    }
  }
}

/* =========================
 *  Sortie JSON / TXT
 * ========================= */
if ($format === 'json') {
  respond([
    'module'  => 'mod_files',
    'root'    => $ROOT,
    'base'    => $base,
    'time'    => date('c'),
    'scanned' => $scanned,
    'count'   => count($rows),
    'rows'    => $rows,
  ], 'json'); exit;
}
if ($format === 'txt') {
  $out = $head;
  foreach ($rows as $r) {
    $out[] = sprintf('%s\t%s\t%s\t%s\t%s',
      $r['severity'], $r['pattern'], shortPath($r['path']),
      $r['size']!==null ? bytesHuman((int)$r['size']) : '—',
      $r['mtime']? date('Y-m-d H:i:s',(int)$r['mtime']) : '—'
    );
  }
  respond(implode("\n",$out)."\n", 'txt'); exit;
}

/* =========================
 *  HTML esthétique
 * ========================= */
header('Content-Type: text/html; charset=UTF-8');
// KPI
$tot = count($rows); $crit=$al=$info=0;
foreach ($rows as $r){ if($r['severity']==='CRITIQUE')$crit++; elseif($r['severity']==='ALERTE')$al++; else $info++; }
// motifs pour filtre
$patternsSet=[]; foreach($rows as $r){ $patternsSet[$r['pattern']]=true; } ksort($patternsSet);
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mod_files — Scan fichiers (contexte)</title>
<style>
:root{--bg:#0f172a;--card:#111827;--muted:#94a3b8;--b:#1f2937;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--info:#60a5fa}
*{box-sizing:border-box}
body{background:var(--bg);color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:0;padding:24px}
h1{margin:0 0 12px} small{color:var(--muted)}
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
</head><body>

<h1>mod_files <small>— scan fichiers PHP (contexte)</small></h1>

<div class="card">
  <div class="grid">
    <div class="kpi"><div class="v"><?=esc((string)$scanned)?></div><div>Fichiers scannés</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$tot)?></div><div>Matches</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$crit)?></div><div class="badge badge-bad">Critiques</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$al)?></div><div class="badge badge-warn">Alertes</div></div>
  </div>
  <div class="controls">
    <input id="q" type="search" placeholder="Filtrer chemin…">
    <select id="lvl">
      <option value="">Tous niveaux</option>
      <option value="CRITIQUE">CRITIQUE</option>
      <option value="ALERTE">ALERTE</option>
      <option value="INFO">INFO</option>
    </select>
    <select id="pat">
      <option value="">Tous motifs</option>
      <?php foreach(array_keys($patternsSet) as $p): ?>
        <option value="<?=esc($p)?>"><?=esc($p)?></option>
      <?php endforeach; ?>
    </select>
    <span class="note">Base: <?=esc(shortPath($base))?> — <?=esc(date('Y-m-d H:i:s'))?> — <span class="nowrap">max=<?=esc((string)$max)?></span></span>
  </div>
</div>

<div class="card">
  <table id="tbl">
    <thead><tr>
      <th>Niveau</th><th>Motif</th><th>Chemin</th><th>Taille</th><th>Modif.</th>
    </tr></thead>
    <tbody>
    <?php foreach ($rows as $r):
      $lvl = $r['severity'];
      $cls = $lvl==='CRITIQUE'?'badge-bad':($lvl==='ALERTE'?'badge-warn':'badge-info');
      $sz  = isset($r['size']) && $r['size']!==null ? bytesHuman((int)$r['size']) : '—';
      $mt  = isset($r['mtime'])&& $r['mtime']? date('Y-m-d H:i:s',(int)$r['mtime']) : '—';
    ?>
      <tr>
        <td><span class="badge <?=$cls?>"><?=esc($lvl)?></span></td>
        <td><?=esc($r['pattern'])?></td>
        <td class="path" title="<?=esc($r['path'])?>"><?=esc($pathOut($r['path']))?></td>
        <td><?=esc($sz)?></td>
        <td><?=esc($mt)?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card">
  <a href="?<?=htmlspecialchars(http_build_query(array_merge($_GET, ['format'=>'json'])), ENT_QUOTES)?>">Exporter JSON</a>
  &nbsp;|&nbsp;
  <a href="?<?=htmlspecialchars(http_build_query(array_merge($_GET, ['format'=>'txt'])), ENT_QUOTES)?>">Exporter texte</a>
  <span class="note"> — Ajoute <code>&max=500</code> si besoin de limiter.</span>
</div>

<script>
// Filtres client
const q   = document.getElementById('q');
const lvl = document.getElementById('lvl');
const pat = document.getElementById('pat');
const rows = Array.from(document.querySelectorAll('#tbl tbody tr'));
function applyFilter(){
  const needle = q.value.toLowerCase();
  const level  = lvl.value;
  const patt   = pat.value;
  rows.forEach(tr => {
    const lvlCell = tr.querySelector('.badge')?.textContent.trim() || '';
    const motif   = tr.children[1]?.textContent.trim() || '';
    const path    = tr.children[2]?.textContent.toLowerCase() || '';
    const okTxt = !needle || path.includes(needle);
    const okLvl = !level || lvlCell === level;
    const okPat = !patt  || motif === patt;
    tr.style.display = (okTxt && okLvl && okPat) ? '' : 'none';
  });
}
[q,lvl,pat].forEach(el => el.addEventListener('input', applyFilter));
lvl.addEventListener('change', applyFilter);
pat.addEventListener('change', applyFilter);
</script>

</body></html>
