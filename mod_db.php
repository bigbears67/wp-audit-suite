<?php declare(strict_types=1);
require __DIR__ . '/audit_config.php';

/**
 * mod_db — audit lecture seule de la base WordPress (prefix courant)
 *
 * Détecte :
 *  - Tables "core" en double / préfixes suspects (ex: wp0ptions, wpposts, prefix_system, etc.)
 *  - Tables hors préfixe attendu mais ressemblant à du core (levenshtein court)
 *  - Options autoload trop lourdes (seuils) + TOP N
 *  - Charges suspectes dans wp_options (base64 long, gzinflate, <php, remote URLs…)
 *  - Cron volumineux (option 'cron')
 *  - Comptes administrateurs (liste informative)
 *  - Taille des tables + TOP N
 *
 * Params:
 *  - key=...                    (obligatoire)
 *  - format=html|txt|json       (défaut: html)
 *  - max=1500                   (plafond lignes renvoyées)
 *  - prefix=xxx_                (défaut: $wpdb->prefix si WP chargé)
 *  - deep=0|1                   (si 1, scanne plus d’items dans options)
 *  - top=50                     (TOP N pour tableaux récapitulatifs)
 */

$format  = strtolower((string)($_GET['format'] ?? 'html'));
$max     = (int)($_GET['max'] ?? DEFAULT_MAX);
$deep    = (int)($_GET['deep'] ?? 0) === 1;
$topN    = max(5, (int)($_GET['top'] ?? 50));
$scanLinks = (int)($_GET['links'] ?? 0) === 1;


$recommend = (int)($_GET['recommend'] ?? 0) === 1;

$tableWarnMB            = (int)($_GET['table_warn_mb'] ?? 8);       // grosses tables
$autoloadWarnTotalMB    = (int)($_GET['autoload_warn_total_mb'] ?? 2);
$autoloadWarnOneKB      = (int)($_GET['autoload_warn_one_kb'] ?? 1024);
$cronWarnMB             = (int)($_GET['cron_warn_mb'] ?? 5);

// conversions
$tableWarnBytes         = max(1, $tableWarnMB) * 1024 * 1024;
$autoloadWarnTotalBytes = max(1, $autoloadWarnTotalMB) * 1024 * 1024;
$autoloadWarnOneBytes   = max(1, $autoloadWarnOneKB) * 1024;
$cronWarnBytes          = max(1, $cronWarnMB) * 1024 * 1024;

/* -------- Connexion & préfixe -------- */
if ($WP_LOADED && isset($GLOBALS['wpdb']) && $GLOBALS['wpdb'] instanceof wpdb) {
  /** @var wpdb $wpdb */
  $wpdb = $GLOBALS['wpdb'];
  $db_name = $wpdb->dbname;
  $dbh     = $wpdb->dbh; // mysqli|resource
  $prefix  = (string)($_GET['prefix'] ?? $wpdb->prefix);
  $prefix  = $prefix !== '' ? $prefix : $wpdb->prefix;
  // petite normalisation
  if ($prefix !== '' && substr($prefix, -1) !== '_') { $prefix .= '_'; }
  $use_wpdb = true;
} else {
  // fallback mysqli via wp-config
  if (!defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASSWORD') || !defined('DB_HOST')) {
    respond("WordPress non chargé et constantes DB_* absentes : impossible de scanner.\n", 'txt', 500);
    exit;
  }
  $mysqli = @mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
  if (!$mysqli) {
    respond("Connexion MySQL échouée: " . @mysqli_connect_error() . "\n", 'txt', 500);
    exit;
  }
  $db_name = DB_NAME;
  $dbh     = $mysqli;
  $prefix  = (string)($_GET['prefix'] ?? 'wp_');
  if ($prefix !== '' && substr($prefix, -1) !== '_') { $prefix .= '_'; }
  $use_wpdb = false;
}

/* -------- Helpers requêtes -------- */
function db_query_all($dbh, string $sql): array {
  if ($dbh instanceof mysqli) {
    $res = $dbh->query($sql);
    if (!$res) return [];
    $rows = [];
    while ($row = $res->fetch_assoc()) $rows[] = $row;
    $res->free();
    return $rows;
  }
  // wpdb
  /** @var wpdb $GLOBALS['wpdb'] */
  $wpdb = $GLOBALS['wpdb'];
  $out = $wpdb->get_results($sql, ARRAY_A);
  return is_array($out) ? $out : [];
}

function esc_like(string $s): string {
  return strtr($s, ['%' => '\%', '_' => '\_', '\\' => '\\\\']);
}

function bytesHumanDB(int $n): string {
  $u = ['B','KB','MB','GB','TB']; $i=0; $f=(float)$n;
  while($f>=1024 && $i<count($u)-1){ $f/=1024; $i++; }
  return rtrim(rtrim(number_format($f,2,'.',''), '0'),'.').' '.$u[$i];
}

/* -------- Collecte -------- */
$rows = []; // lignes de findings
$push = function(array $r) use (&$rows, $max) {
  if (count($rows) < $max) $rows[] = $r;
};

$now = date('Y-m-d H:i:s');
$head = [
  "# mod_db — audit DB",
  "DB: {$db_name} | Prefix: {$prefix} | {$now}"
];

/* =========================
 *  0) Domaines externes (posts/pages) — optionnel via &links=1
 * ========================= */
$externalDomains = [];
$siteHost = null;
if ($scanLinks) {
  // Déduire domaine du site
  if ($WP_LOADED && function_exists('home_url')) {
    $siteUrl = home_url('/');
  } else {
    $opt = db_query_all($dbh, "SELECT option_value FROM `{$prefix}options` WHERE option_name IN ('home','siteurl') ORDER BY CASE option_name WHEN 'home' THEN 0 ELSE 1 END LIMIT 1");
    $siteUrl = $opt[0]['option_value'] ?? '';
  }
  $siteHost = parse_url((string)$siteUrl, PHP_URL_HOST);
  $siteHost = $siteHost ? strtolower(preg_replace('/^www\./','',$siteHost)) : null;

  $sql = "SELECT ID, post_title, post_type, post_status, post_content
          FROM `{$prefix}posts`
          WHERE post_status IN ('publish','inherit') AND post_content REGEXP 'https?://'
          LIMIT {$max}";
  $posts = db_query_all($dbh, $sql);
  foreach ($posts as $p) {
    $content = (string)$p['post_content'];
    if ($content === '') continue;
    if (preg_match_all('~https?://[^\s"\'<>\)\(]+~i', $content, $m)) {
      foreach ($m[0] as $url) {
        $parts = @parse_url($url);
        if (!$parts || empty($parts['host'])) continue;
        $host = strtolower(preg_replace('/^www\./','',$parts['host']));
        if ($siteHost && $host === $siteHost) continue;
        if (filter_var($host, FILTER_VALIDATE_IP)) {
          if (preg_match('/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/', $host)) continue;
        }
        if (!isset($externalDomains[$host])) $externalDomains[$host] = ['count'=>0,'examples'=>[]];
        $externalDomains[$host]['count']++;
        if (count($externalDomains[$host]['examples']) < 3) {
          $externalDomains[$host]['examples'][] = [
            'id'    => (int)$p['ID'],
            'title' => (string)$p['post_title'],
            'url'   => (string)$url,
          ];
        }
      }
    }
  }
  uasort($externalDomains, function($a,$b){ return $b['count'] <=> $a['count']; });
}

/* =========================
 *  1) Inventaire tables & préfixes
 * ========================= */
$schema = addslashes($db_name);
$sqlTables = "
  SELECT table_name, engine, table_rows, data_length, index_length, create_time, table_collation
  FROM information_schema.tables
  WHERE table_schema = '{$schema}'
  ORDER BY table_name
";
$tables = db_query_all($dbh, $sqlTables);

$coreNames = [
  'options','users','usermeta','posts','postmeta','terms','termmeta',
  'term_taxonomy','term_relationships','comments','commentmeta','links'
];

// repérage préfixes présents
$prefixCounts = [];
foreach ($tables as $t) {
  $name = $t['table_name'];
  if (preg_match('/^([a-zA-Z0-9_]+_)/', $name, $m)) {
    $p = $m[1];
  } else {
    $p = '';
  }
  $prefixCounts[$p] = ($prefixCounts[$p] ?? 0) + 1;
}

// tables avec notre préfixe
$mine = [];
$others = [];
foreach ($tables as $t) {
  $name = $t['table_name'];
  if (strpos($name, $prefix) === 0) $mine[] = $t; else $others[] = $t;
}

// tables “core” attendues
$expectedCore = array_map(fn($n) => $prefix.$n, $coreNames);

// 1.a) Tables core manquantes (INFO)
foreach ($expectedCore as $core) {
  $found = false;
  foreach ($mine as $t) if ($t['table_name'] === $core) { $found = true; break; }
  if (!$found) {
    $push(['severity'=>'INFO','type'=>'core_missing','object'=>$core,'detail'=>'Table core non trouvée (peut être normal selon contexte)']);
  }
}

// 1.b) Tables look-alike (ALERTE): ressemblent à du core mais orthographe modifiée (levenshtein 1-2)
foreach ($others as $t) {
  $name = $t['table_name'];
  // repérer les noms qui finissent par un nom "core" altéré
  foreach ($coreNames as $cn) {
    // normalisé (remplacer 0->o, 1->l/i)
    $norm = function(string $x){ return strtr(strtolower($x), ['0'=>'o','1'=>'l','5'=>'s']); };
    $tail = substr($name, -strlen($cn));
    if ($tail === '') continue;
    $d = levenshtein($norm($tail), $norm($cn));
    if ($d <= 2 && $tail !== $cn) {
      $size = (int)$t['data_length'] + (int)$t['index_length'];
      $push([
        'severity'=>'ALERTE',
        'type'=>'lookalike_core_table',
        'object'=>$name,
        'detail'=>"Rappelle '{$cn}' (distance={$d})",
        'size'=>$size,
        'extra'=>['engine'=>$t['engine'],'collation'=>$t['table_collation']]
      ]);
      break;
    }
  }
}

// 1.c) Tables “prefix_system* / backup / shadow” sous notre préfixe (ALERTE)
foreach ($mine as $t) {
  $name = $t['table_name'];
  $short = substr($name, strlen($prefix));
  if (preg_match('/^(system|shadow|backup|bak|tmp|old|copy|test)\b/i', $short)) {
    $size = (int)$t['data_length'] + (int)$t['index_length'];
    $push([
      'severity'=>'ALERTE','type'=>'suspicious_prefix_table','object'=>$name,
      'detail'=>"Nom anormal sous préfixe ({$short})",'size'=>$size
    ]);
  }
}

/* =========================
 *  2) Options autoload & charges suspectes
 * ========================= */
$tblOptions = $prefix . 'options';

// 2.a) Somme autoload + TOP N lourdes
$sumAutoload = db_query_all($dbh, "SELECT SUM(LENGTH(option_value)) AS s FROM `{$tblOptions}` WHERE autoload='yes'");
$totalAutoload = (int)($sumAutoload[0]['s'] ?? 0);

$topLimit = $deep ? $topN : min($topN, 25);
$topAuto = db_query_all($dbh, "
  SELECT option_name, LENGTH(option_value) AS len
  FROM `{$tblOptions}`
  WHERE autoload='yes'
  ORDER BY len DESC
  LIMIT {$topLimit}
");

$thresholdTotal = 2*1024*1024; // 2 MB
$thresholdOne   = 1*1024*1024; // 1 MB

if ($totalAutoload > $thresholdTotal) {
  $push(['severity'=>'ALERTE','type'=>'autoload_total','object'=>$tblOptions,'detail'=>'Total autoload élevé','size'=>$totalAutoload]);
}
foreach ($topAuto as $r) {
  $sev = ((int)$r['len'] >= $thresholdOne) ? 'ALERTE' : 'INFO';
  $push(['severity'=>$sev,'type'=>'autoload_heavy_option','object'=>$tblOptions,'detail'=>$r['option_name'],'size'=>(int)$r['len']]);
}

// 2.b) Charges suspectes (REGEXP simples, limitées)
$limitScan = $deep ? 200 : 80; // nombre d’options max à remonter par motif
$susp = [
  ['base64_long', "REGEXP", "base64_decode\\s*\\(\\s*'[A-Za-z0-9+/=]{400,}'"],
  ['gzinflate',   "LIKE",   "%gzinflate(%"],
  ['php_tag',     "LIKE",   "%<?php%"],
  ['preg_e',      "REGEXP", "preg_replace\\s*\\([^)]*/[imsxADSUXu]*e[imsxADSUXu]*['\"]\\s*\\)"],
  ['remote_url',  "REGEXP", "https?://[^\\s'\"]+"],
];
foreach ($susp as [$label,$op,$pat]) {
  if ($op === 'LIKE') {
    $q = "SELECT option_name, LENGTH(option_value) AS len
          FROM `{$tblOptions}`
          WHERE option_value LIKE '".addslashes($pat)."'
          ORDER BY len DESC LIMIT {$limitScan}";
  } else {
    $q = "SELECT option_name, LENGTH(option_value) AS len
          FROM `{$tblOptions}`
          WHERE option_value {$op} '{$pat}'
          ORDER BY len DESC LIMIT {$limitScan}";
  }
  $hits = db_query_all($dbh, $q);
  foreach ($hits as $h) {
    $sev = ($label==='base64_long') ? 'ALERTE' : 'INFO';
    $push(['severity'=>$sev,'type'=>"opt_{$label}",'object'=>$tblOptions,'detail'=>$h['option_name'],'size'=>(int)$h['len']]);
  }
}

// 2.c) Cron volumineux
$cron = db_query_all($dbh, "SELECT LENGTH(option_value) AS len FROM `{$tblOptions}` WHERE option_name='cron' LIMIT 1");
if ($cron) {
  $len = (int)$cron[0]['len'];
  if ($len > 5*1024*1024) {
    $push(['severity'=>'ALERTE','type'=>'cron_large','object'=>$tblOptions,'detail'=>'option_name=cron','size'=>$len]);
  } elseif ($len > 1*1024*1024) {
    $push(['severity'=>'INFO','type'=>'cron_large','object'=>$tblOptions,'detail'=>'option_name=cron','size'=>$len]);
  }
}

/* =========================
 *  3) Comptes administrateurs (inform.)
 * ========================= */
$tblUsers   = $prefix.'users';
$tblUMeta   = $prefix.'usermeta';
$capKeyLike = $prefix.'capabilities';

$admins = db_query_all($dbh, "
  SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value AS caps
  FROM `{$tblUsers}` u
  JOIN `{$tblUMeta}` m ON (m.user_id=u.ID AND m.meta_key='".addslashes($capKeyLike)."')
  WHERE m.meta_value LIKE '%administrator%'
  ORDER BY u.user_registered DESC
  LIMIT ".($deep?200:50)
);
foreach ($admins as $a) {
  $detail = $a['user_login'].' <'.$a['user_email'].'>';
  $push(['severity'=>'INFO','type'=>'admin_user','object'=>$tblUsers,'detail'=>$detail,'extra'=>['id'=>$a['ID'],'registered'=>$a['user_registered']]]);
}

/* =========================
 *  4) Tables les plus lourdes (TOP N)
 * ========================= */
$topTables = $tables;
usort($topTables, function($A,$B){
  $sa = (int)$A['data_length'] + (int)$A['index_length'];
  $sb = (int)$B['data_length'] + (int)$B['index_length'];
  return $sb <=> $sa;
});
$topTables = array_slice($topTables, 0, $topN);
foreach ($topTables as $t) {
  $size = (int)$t['data_length'] + (int)$t['index_length'];
  $push(['severity'=>'INFO','type'=>'table_size_top','object'=>$t['table_name'],'detail'=>$t['engine'].' / '.$t['table_collation'],'size'=>$size]);
}
/* =========================
 *  5) Recommandations (lecture seule)
 * ========================= */
$advice = []; // chaque item: ['severity','title','why','suggestions'=>[...]] (texte uniquement)

// A) Autoload
if (isset($totalAutoload) && $totalAutoload > $autoloadWarnTotalBytes) {
  $advice[] = [
    'severity'    => 'ALERTE',
    'title'       => 'Autoload total élevé',
    'why'         => 'Le chargement automatique des options dépasse ' . bytesHumanDB($autoloadWarnTotalBytes) . ' (observé: ' . bytesHumanDB($totalAutoload) . ').',
    'suggestions' => [
      "Lister les options autoload lourdes (TOP 50) via le module ou WP-CLI :",
      "wp option list --autoload=on --fields=option_name,size_bytes --format=json | jq 'sort_by(.size_bytes)|reverse|.[0:50]'",
      "Vérifier si certaines options peuvent passer en autoload='no' (uniquement si non requises au bootstrap)."
    ]
  ];
}
// Autoload one heavy options
if (!empty($topAuto)) {
  foreach ($topAuto as $r) {
    $len = (int)$r['len'];
    if ($len >= $autoloadWarnOneBytes) {
      $advice[] = [
        'severity'    => 'ALERTE',
        'title'       => "Option autoload lourde : {$r['option_name']}",
        'why'         => 'Taille : ' . bytesHumanDB($len) . ' ≥ ' . bytesHumanDB($autoloadWarnOneBytes) . '.',
        'suggestions' => [
          "Vérifier l’utilité réelle de cette option au chargement de toutes les pages.",
          "Diagnostic SQL (lecture seule) :",
          "SELECT LENGTH(option_value) AS len FROM `{$tblOptions}` WHERE option_name='" . addslashes($r['option_name']) . "';"
        ]
      ];
    }
  }
}

// B) Cron volumineux
if (!empty($cron)) {
  $len = (int)$cron[0]['len'];
  if ($len > $cronWarnBytes) {
    $advice[] = [
      'severity'    => 'ALERTE',
      'title'       => "Option 'cron' volumineuse",
      'why'         => 'Taille : ' . bytesHumanDB($len) . ' (> ' . bytesHumanDB($cronWarnBytes) . ').',
      'suggestions' => [
        "Contrôler les jobs récurrents bruyants (plugins d’automation/SEO/analytics).",
        "WP-CLI (lecture): wp cron event list",
        "Si Action Scheduler est utilisé massivement, voir les conseils associés ci-dessous."
      ]
    ];
  }
}

// C) Tables bien connues : Action Scheduler, FluentSMTP logs, etc.
$tblByName = [];
foreach ($tables as $t) { $tblByName[$t['table_name']] = (int)$t['data_length'] + (int)$t['index_length']; }

$asActions = $prefix.'actionscheduler_actions';
$asLogs    = $prefix.'actionscheduler_logs';
if (isset($tblByName[$asActions]) && $tblByName[$asActions] > $tableWarnBytes) {
  $advice[] = [
    'severity'    => 'ALERTE',
    'title'       => 'Action Scheduler — table actions lourde',
    'why'         => 'Taille de ' . bytesHumanDB($tblByName[$asActions]) . ' (> ' . bytesHumanDB($tableWarnBytes) . ').',
    'suggestions' => [
      "WP-CLI (lecture/gestion):",
      "wp action-scheduler run",
      "wp action-scheduler list --status=complete --format=table | head -n 50",
      "Piste: réduire la rétention des actions terminées dans les plugins qui s’appuient dessus."
    ]
  ];
}
if (isset($tblByName[$asLogs]) && $tblByName[$asLogs] > $tableWarnBytes) {
  $advice[] = [
    'severity'    => 'ALERTE',
    'title'       => 'Action Scheduler — table logs lourde',
    'why'         => 'Taille de ' . bytesHumanDB($tblByName[$asLogs]) . ' (> ' . bytesHumanDB($tableWarnBytes) . ').',
    'suggestions' => [
      "WP-CLI (lecture): wp action-scheduler list --status=failed --format=table | head -n 50",
      "Piste: réduire la rétention des logs (paramètres du/des plugins)."
    ]
  ];
}

// FluentSMTP logs
$fsmpt = $prefix.'fsmpt_email_logs';
if (isset($tblByName[$fsmpt]) && $tblByName[$fsmpt] > $tableWarnBytes) {
  $advice[] = [
    'severity'    => 'ALERTE',
    'title'       => 'FluentSMTP — logs volumineux',
    'why'         => 'Taille de ' . bytesHumanDB($tblByName[$fsmpt]) . ' (> ' . bytesHumanDB($tableWarnBytes) . ').',
    'suggestions' => [
      "Revoir la rétention des logs dans FluentSMTP (14–30 jours).",
      "Lecture seule (exemples):",
      "SELECT COUNT(*) FROM `{$fsmpt}`;"
    ]
  ];
}

// D) Posts/Postmeta
$posts   = $prefix.'posts';
$postmeta= $prefix.'postmeta';
if (isset($tblByName[$posts]) && $tblByName[$posts] > $tableWarnBytes) {
  $advice[] = [
    'severity'    => 'INFO',
    'title'       => 'Table posts importante',
    'why'         => 'Taille de ' . bytesHumanDB($tblByName[$posts]) . ' (> ' . bytesHumanDB($tableWarnBytes) . ').',
    'suggestions' => [
      "Diagnostic (lecture): compter révisions, corbeilles.",
      "WP-CLI: wp post list --post_type='revision' --format=count",
      "WP-CLI: wp post list --post_status='trash' --format=count"
    ]
  ];
}
if (isset($tblByName[$postmeta]) && $tblByName[$postmeta] > $tableWarnBytes) {
  $advice[] = [
    'severity'    => 'INFO',
    'title'       => 'Table postmeta importante',
    'why'         => 'Taille de ' . bytesHumanDB($tblByName[$postmeta]) . ' (> ' . bytesHumanDB($tableWarnBytes) . ').',
    'suggestions' => [
      "Diagnostic (lecture) — métas orphelines :",
      "SELECT COUNT(*) FROM `{$postmeta}` pm LEFT JOIN `{$posts}` p ON p.ID=pm.post_id WHERE p.ID IS NULL;"
    ]
  ];
}




/* =========================
 *  Sorties JSON / TXT
 * ========================= */
if ($format === 'json') {
  $payload = [
    'module'  => 'mod_db',
    'db'      => $db_name,
    'prefix'  => $prefix,
    'time'    => date('c'),
    'count'   => count($rows),
    'rows'    => $rows,
    'prefixes'=> $prefixCounts,
  ];
  if ($scanLinks) {
    $payload['external_domains'] = [
      'site_host' => $siteHost,
      'top' => array_slice($externalDomains, 0, $topN, true)
    ];
  }
  if ($recommend) {
    $payload['advice'] = $advice;
    $payload['thresholds'] = [
      'table_warn_mb' => $tableWarnMB,
      'autoload_total_mb' => $autoloadWarnTotalMB,
      'autoload_one_kb' => $autoloadWarnOneKB,
      'cron_warn_mb' => $cronWarnMB,
    ];
  }
  respond($payload, 'json'); exit;
}


if ($format === 'txt') {
  $out = $head;
  foreach ($rows as $r) {
    $size = isset($r['size']) ? bytesHumanDB((int)$r['size']) : '—';
    $extra= isset($r['extra']) ? json_encode($r['extra']) : '';
    $out[] = sprintf("%s\t%s\t%s\t%s\t%s\t%s",
      $r['severity'],
      $r['type'],
      $r['object'],
      $size,
      $r['detail'] ?? '',
      $extra
    );
  }
  respond(implode("\n", $out)."\n", 'txt'); exit;
}

/* =========================
 *  HTML esthétique
 * ========================= */
header('Content-Type: text/html; charset=UTF-8');

// KPI
$tot = count($rows); $crit=$al=$info=0;
foreach ($rows as $r){ if($r['severity']==='CRITIQUE')$crit++; elseif($r['severity']==='ALERTE')$al++; else $info++; }

// Types pour filtre
$types = []; foreach($rows as $r){ $types[$r['type']] = true; } ksort($types);

// Prefix list
arsort($prefixCounts);

?>
<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mod_db — Audit DB (prefix <?=esc($prefix)?>)</title>
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
td.size{white-space:nowrap}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
input[type="search"], select{background:#0b1220;border:1px solid var(--b);border-radius:8px;padding:8px;color:#e2e8f0}
.note{color:var(--muted);font-size:12px}
.nowrap{white-space:nowrap}
.small{font-size:12px;color:var(--muted)}
.prefixes{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.prefixes .chip{background:#0b1220;border:1px solid var(--b);border-radius:999px;padding:4px 8px}
</style>
</head>
<body>

<h1>mod_db <small>— audit DB (prefix <?=esc($prefix)?>)</small></h1>
<div style="margin-bottom: 16px;">
  <button onclick="history.back()" style="background: #0b1220; border: 1px solid #1f2937; border-radius: 10px; padding: 10px 14px; color: #e2e8f0; font-family: inherit; font-size: 14px; cursor: pointer;">
    &larr; Précédent
  </button>
</div>
<div class="card">
  <div class="grid">
    <div class="kpi"><div class="v"><?=esc((string)count($tables))?></div><div>Tables dans DB</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$tot)?></div><div>Détections</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$al)?></div><div class="badge badge-warn">Alertes</div></div>
    <div class="kpi"><div class="v"><?=esc((string)$info)?></div><div class="badge badge-info">Infos</div></div>
  
</div>

<?php if ($scanLinks): ?>
<div class="card">
  <h3 style="margin:0 0 8px 0">Domaines externes référencés</h3>
  <div class="small">Site : <code><?=esc((string)($siteHost ?? '—'))?></code> — internes exclus. Paramètres : <code>&links=1</code>, <code>&max=<?=esc((string)$max)?></code>, <code>&top=<?=esc((string)$topN)?></code>.</div>
  <?php if (empty($externalDomains)): ?>
    <div class="note">Aucun domaine externe détecté dans la limite actuelle.</div>
  <?php else: ?>
  <table style="width:100%;border-collapse:collapse;margin-top:8px">
    <thead>
      <tr>
        <th style="text-align:left;border-bottom:1px solid var(--b);padding:6px 8px">Domaine</th>
        <th style="text-align:right;border-bottom:1px solid var(--b);padding:6px 8px;width:110px">Occur.</th>
        <th style="text-align:left;border-bottom:1px solid var(--b);padding:6px 8px">Exemples</th>
      </tr>
    </thead>
    <tbody>
      <?php $n=0; foreach ($externalDomains as $dom=>$data): if (++$n>$topN) break; ?>
      <tr>
        <td style="padding:6px 8px"><code><?=esc($dom)?></code></td>
        <td style="padding:6px 8px;text-align:right"><span class="badge badge-info"><?=esc((string)$data['count'])?></span></td>
        <td style="padding:6px 8px">
          <?php foreach ($data['examples'] as $ex): ?>
            <div class="small">[#<?=esc((string)$ex['id'])?>] <?=esc($ex['title'] ?: '(sans titre)')?> — <a href="<?=esc($ex['url'])?>" target="_blank" rel="noopener noreferrer"><?=esc($ex['url'])?></a></div>
          <?php endforeach; ?>
        </td>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>
<?php endif; ?>

	<?php if ($recommend): ?>

<div class="card">
  <h3 style="margin-top:0">Recommandations (lecture seule)</h3>
  <?php if (empty($advice)): ?>
    <div class="note">Aucune recommandation particulière aux seuils courants.</div>
  <?php else: ?>
    <?php foreach ($advice as $a):
      $lvl = $a['severity'];
      $cls = $lvl==='CRITIQUE'?'badge-bad':($lvl==='ALERTE'?'badge-warn':'badge-info');
    ?>
      <div style="border:1px solid var(--b);border-radius:10px;padding:12px;margin:10px 0;background:#0b1220">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <span class="badge <?=$cls?>"><?=esc($lvl)?></span>
          <strong><?=esc($a['title'])?></strong>
        </div>
        <div class="note" style="margin-bottom:8px"><?=esc($a['why'])?></div>
        <?php if (!empty($a['suggestions'])): ?>
          <ul style="margin:0 0 6px 18px;padding:0">
          <?php foreach ($a['suggestions'] as $s): ?>
            <li><code><?=esc($s)?></code></li>
          <?php endforeach; ?>
          </ul>
        <?php endif; ?>
      </div>
    <?php endforeach; ?>
  <?php endif; ?>
  <div class="note">Seuils : grosses tables &ge; <?=esc((string)$tableWarnMB)?> MB — autoload total &ge; <?=esc((string)$autoloadWarnTotalMB)?> MB — option autoload &ge; <?=esc((string)$autoloadWarnOneKB)?> KB — cron &ge; <?=esc((string)$cronWarnMB)?> MB.</div>
</div>
<?php endif; ?>

  <div class="controls">
    <input id="q" type="search" placeholder="Filtrer (type/objet/détail)…">
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
      DB: <?=esc($db_name)?> — Prefix: <?=esc($prefix)?> — <?=esc($now)?> — <span class="nowrap">max=<?=esc((string)$max)?></span>
    </span>
    <div class="prefixes">
      <?php foreach ($prefixCounts as $p=>$c): ?>
        <span class="chip"><b><?=esc($p ?: '(sans prefix)')?></b> : <?=esc((string)$c)?></span>
      <?php endforeach; ?>
    </div>
    <div class="small">Changer de préfixe : ajoute <code>&prefix=xxx_</code> à l’URL. Profondeur : <code>&deep=1</code>. TOP N : <code>&top=100</code>.</div>
  </div>
</div>

<div class="card">
  <table id="tbl">
    <thead>
      <tr>
        <th>Niveau</th>
        <th>Type</th>
        <th>Objet</th>
        <th>Taille</th>
        <th>Détail</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $r):
      $lvl = $r['severity'];
      $cls = $lvl==='CRITIQUE'?'badge-bad':($lvl==='ALERTE'?'badge-warn':'badge-info');
      $sz  = isset($r['size']) ? bytesHumanDB((int)$r['size']) : '—';
      $obj = $r['object'] ?? '—';
      $det = $r['detail'] ?? '';
    ?>
      <tr>
        <td><span class="badge <?=$cls?>"><?=esc($lvl)?></span></td>
        <td><?=esc($r['type'])?></td>
        <td><?=esc($obj)?></td>
        <td class="size"><?=esc($sz)?></td>
        <td><?=esc($det)?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>

<div class="card">
  <a href="?<?=htmlspecialchars(http_build_query(array_merge($_GET, ['format'=>'json'])), ENT_QUOTES)?>">Exporter JSON</a>
  &nbsp;|&nbsp;
  <a href="?<?=htmlspecialchars(http_build_query(array_merge($_GET, ['format'=>'txt'])), ENT_QUOTES)?>">Exporter texte</a>
  <span class="note"> — Paramètres: <code>&prefix=xxx_</code> <code>&deep=1</code> <code>&top=100</code>.</span>
</div>
<div class="card">
  <div class="note">
    🔔 Rappel : WP Audit Suite est un outil d’audit <b>lecture seule</b>. Ne le laissez pas en production :
    <b>supprimez</b> les fichiers une fois l’audit terminé.
  </div>
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
    const txt     = tr.innerText.toLowerCase();
    const okTxt = !needle || txt.includes(needle);
    const okLvl = !level  || lvlCell === level;
    const okTyp = !type   || typeCell === type;
    tr.style.display = (okTxt && okLvl && okTyp) ? '' : 'none';
  });
}
[q,lvl,typ].forEach(el => el.addEventListener('input', applyFilter));
lvl.addEventListener('change', applyFilter);
typ.addEventListener('change', applyFilter);
</script>

</body></html>
