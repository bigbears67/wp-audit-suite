<?php
/**
 * WP Audit Suite — mod_data.php (corrected)
 * Analyse (lecture seule) des données structurées: JSON-LD, Microdata, RDFa
 *
 * Paramètres :
 *   ?key=VOTRE_AUDIT_KEY
 *   &max=50
 *   &include_sitemap=1
 *   &test_logo_size=0
 */

// 1) Charger la config commune
$cfgFile = __DIR__ . '/audit_config.php';
if (is_readable($cfgFile)) {
    require_once $cfgFile;
}

// 1.b) Secours: helpers minimaux si absents
if (!function_exists('h')) { function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); } }
if (!function_exists('truncate')) {
    function truncate($s, $max=700){
        $s = (string)$s; if (strlen($s) <= $max) return $s; return substr($s, 0, $max-3) . '...';
    }
}
if (!function_exists('badge')) {
    function badge($label, $type='default'){
        $colors = [
            'OK' => '#16a34a', 'INFO' => '#2563eb', 'ALERTE' => '#d97706', 'CRITIQUE' => '#dc2626', 'default' => '#334155'
        ];
        $c = $colors[$type] ?? $colors['default'];
        return '<span style="display:inline-block;padding:2px 8px;border-radius:9999px;background:'.$c.';color:#fff;font:12px/1.4 system-ui,Segoe UI,Roboto,Helvetica,Arial">'.h($label).'</span>';
    }
}
if (!function_exists('print_header')) {
    function print_header($title='WP Audit Suite — Données structurées'){
        $titleEsc = h($title);
        $html = <<<'HTML'
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--fg:#0f172a;--muted:#475569;--bg:#0b1220;--card:#0f172a;--row:#0b1220;--ok:#16a34a;}
body{margin:0;background:#0a0f1a;color:#e5e7eb;font:14px/1.6 system-ui,Segoe UI,Roboto,Helvetica,Arial}
a{color:#93c5fd;text-decoration:none} a:hover{text-decoration:underline}
header{padding:18px 22px;border-bottom:1px solid #1f2937;background:#0b1220;position:sticky;top:0;z-index:2}
h1{margin:0;font-size:18px}
.wrap{padding:20px}
.card{background:#0f172a;border:1px solid #1f2937;border-radius:12px;padding:16px;margin:0 0 16px 0}
table{width:100%;border-collapse:separate;border-spacing:0}
th,td{padding:10px 12px;vertical-align:top}
th{position:sticky;top:62px;background:#0f172a;border-bottom:1px solid #1f2937;text-align:left}
tr:nth-child(odd){background:#0b1220}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word}
.grid{display:grid;gap:12px}
.grid2{grid-template-columns:repeat(2,minmax(0,1fr))}
.muted{color:#94a3b8}
.small{font-size:12px}
.kpi{display:flex;gap:12px;flex-wrap:wrap}
.kpi>div{flex:1 1 160px;background:#0f172a;border:1px solid #1f2937;border-radius:12px;padding:12px}
</style>
<title>
HTML;
        echo $html.$titleEsc;
        echo <<<HTML
</title>
</head>
<body>
<header><h1>$titleEsc</h1></header>
<div style="margin-bottom: 16px;">
  <button onclick="history.back()" style="background: #0b1220; border: 1px solid #1f2937; border-radius: 10px; padding: 10px 14px; color: #e2e8f0; font-family: inherit; font-size: 14px; cursor: pointer;">
    &larr; Précédent
  </button>
</div>
<div class="wrap">
HTML;
    }
}
if (!function_exists('print_footer')) { function print_footer(){ echo "</div></body></html>"; } }
if (!function_exists('enforce_auth_or_exit')) {
    function enforce_auth_or_exit(){
        if (!defined('AUDIT_KEY')) return; // si pas de clé définie dans la config, ne bloque pas (site de test)
        $key = $_GET['key'] ?? '';
        if (!hash_equals((string)AUDIT_KEY, (string)$key)){
            http_response_code(403);
            die('<meta charset="utf-8"><style>body{background:#0a0f1a;color:#e5e7eb;font:14px system-ui;padding:32px}</style><h1>403</h1><p>Clé d\'audit invalide.</p>');
        }
    }
}
if (!function_exists('detect_site_base_url')) {
    function detect_site_base_url(){
        if (defined('WP_HOME')) return rtrim(WP_HOME,'/');
        if (defined('WP_SITEURL')) return rtrim(WP_SITEURL,'/');
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        return $scheme.'://'.$host;
    }
}
if (!function_exists('http_get_local')) {
    function http_get_local($url, $timeout=6){
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_USERAGENT => 'WP-Audit-Suite/mod_data (+https://webmaster67.fr)'
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($code >= 200 && $code < 400) return $body;
        return '';
    }
}
if (!function_exists('fetch_urls_from_sitemaps')) {
    function fetch_urls_from_sitemaps($base){
        $out = [];
        $candidates = [
            $base.'/sitemap_index.xml',
            $base.'/sitemap.xml',
            $base.'/sitemap1.xml',
        ];
        $seen = [];
        foreach ($candidates as $sm) {
            $xml = http_get_local($sm, 5);
            if (!$xml) continue;
            if (!preg_match_all('#<loc>([^<]+)</loc>#i', $xml, $m)) continue;
            foreach ($m[1] as $loc) {
                $loc = trim($loc);
                if (isset($seen[$loc])) continue; $seen[$loc]=1;
                if (preg_match('#sitemap\-?\d*\.xml$#i', $loc) && $loc !== $sm) {
                    $sub = http_get_local($loc,5);
                    if ($sub && preg_match_all('#<loc>([^<]+)</loc>#i', $sub, $m2)){
                        foreach ($m2[1] as $u) { $u=trim($u); if (!isset($seen[$u])) { $seen[$u]=1; $out[]=$u; } }
                    }
                } else {
                    $out[] = $loc;
                }
            }
        }
        $out = array_values(array_filter($out, function($u){ return preg_match('#^https?://#i',$u); }));
        return $out;
    }
}
if (!function_exists('fetch_urls_from_wpdb')) {
    function fetch_urls_from_wpdb($max=50){
        $urls = [];
        $root = dirname(__DIR__);
        $wpConfig = $root.'/wp-config.php';
        if (!is_readable($wpConfig)) {
            $wpConfig = __DIR__.'/wp-config.php';
        }
        if (!is_readable($wpConfig)) return $urls;
        include_once $wpConfig;
        if (!defined('DB_NAME')) return $urls;
        $mysqli = @new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, defined('DB_PORT')?DB_PORT:3306);
        if ($mysqli->connect_errno) return $urls;
        $mysqli->set_charset('utf8mb4');
        $prefix = defined('table_prefix') ? table_prefix : 'wp_';
        $max = max(1, (int)$max);
        $sql = "SELECT ID, post_type, post_name FROM {$prefix}posts WHERE post_status='publish' AND post_type IN ('page','post','product') ORDER BY post_date_gmt DESC LIMIT ".$max;
        if ($res = $mysqli->query($sql)){
            $home = '';
            if ($r2 = $mysqli->query("SELECT option_value FROM {$prefix}options WHERE option_name='home'")){
                $row=$r2->fetch_row(); $home = rtrim($row[0] ?? '', '/'); $r2->close();
            }
            while ($row = $res->fetch_assoc()){
                $slug = $row['post_name'];
                $type = $row['post_type'];
                if ($type==='page')        $urls[] = $home.'/'.rawurlencode($slug);
                elseif ($type==='post')    $urls[] = $home.'/'.rawurlencode($slug);
                elseif ($type==='product') $urls[] = $home.'/product/'.rawurlencode($slug);
            }
            $res->close();
        }
        $mysqli->close();
        return array_values(array_unique(array_filter($urls)));
    }
}

// 2) Auth
enforce_auth_or_exit();

// 3) Paramètres
$max           = max(1, (int)($_GET['max'] ?? (defined('DEFAULT_MAX')?DEFAULT_MAX:50)));
$useSitemap    = (int)($_GET['include_sitemap'] ?? 1) === 1;
$testLogoSize  = (int)($_GET['test_logo_size'] ?? 0) === 1;

$base = detect_site_base_url();

// 4) Collecte des URLs
$urls = [];
if ($useSitemap) {
    $urls = fetch_urls_from_sitemaps($base);
}
if (!$urls) {
    $urls = fetch_urls_from_wpdb($max);
}
if (!$urls) { $urls = [$base]; }
array_unshift($urls, $base);
$urls = array_values(array_unique($urls));
$urls = array_slice($urls, 0, $max);

// 5) Scan
$results = [];
$stats = [ 'pages'=>0, 'items'=>0, 'ok'=>0, 'info'=>0, 'warn'=>0, 'crit'=>0 ];

print_header('WP Audit Suite — Données structurées (mod_data.php)');

echo '<div class="card kpi">';
    echo '<div><div class="muted small">Base URL</div><div>'.h($base).'</div></div>';
    echo '<div><div class="muted small">Pages ciblées (max)</div><div>'.h((string)$max).'</div></div>';
    echo '<div><div class="muted small">Source</div><div>'.($useSitemap?'Sitemap &amp; DB':'DB uniquement').'</div></div>';
    echo '<div><div class="muted small">Test taille logo</div><div>'.($testLogoSize?'Activé':'Non').'</div></div>';
echo '</div>';

foreach ($urls as $u){
    $stats['pages']++;
    $html = http_get_local($u);
    if (!$html){
        $results[] = [ 'url'=>$u, 'type'=>'-', 'status'=>'CRITIQUE', 'issues'=>['Page inaccessible'], 'sample'=>'' ];
        $stats['crit']++; continue;
    }
    [$itemsJsonLd, $itemsMicro, $itemsRdfa] = extract_structured_data($html);
    $items = normalize_structured_data(array_merge($itemsJsonLd, $itemsMicro, $itemsRdfa), $u);
    if (!$items) {
        $results[] = [ 'url'=>$u, 'type'=>'-', 'status'=>'INFO', 'issues'=>['Aucun bloc de données structurées détecté'], 'sample'=>'' ];
        $stats['info']++; continue;
    }
    foreach ($items as $it){
        $stats['items']++;
        $check = validate_schema_item($it, $base, $testLogoSize);
        $st = $check['status'];
        if ($st==='OK') $stats['ok']++; elseif ($st==='INFO') $stats['info']++; elseif ($st==='ALERTE') $stats['warn']++; else $stats['crit']++;
        $results[] = [
            'url'=>$u,
            'type'=> is_array($it['@type'] ?? null) ? implode(',', $it['@type']) : ($it['@type'] ?? 'Unknown'),
            'status'=>$st,
            'issues'=>$check['issues'],
            'sample'=> truncate(json_encode($it, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE), 900),
        ];
    }
}

// 6) Corrélations globales minimales (doublons Organization)
$global = correlate_global_inconsistencies($results);

// 7) Rendu
render_results_table($results, $global, $stats);
print_footer();

// ==============================
// Extracteurs & Normalisation
// ==============================
function extract_structured_data($html){
    $jsonld = [];
    if (preg_match_all('#<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>#is', $html, $m)){
        foreach ($m[1] as $raw){
            $raw = trim($raw);
            $raw = preg_replace("#,\\s*([}\\]])#m", '$1', $raw);
            $data = json_decode($raw, true);
            if (json_last_error() !== JSON_ERROR_NONE) continue;
            if (!$data) continue;
            if (isset($data['@graph']) && is_array($data['@graph'])){
                foreach ($data['@graph'] as $g){ $jsonld[] = $g; }
            } else {
                $jsonld[] = $data;
            }
        }
    }
    $micro = [];$rdfa = [];
    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    if ($dom->loadHTML($html)){
        $xp = new DOMXPath($dom);
        foreach ($xp->query('//*[@itemscope and @itemtype]') as $node){
            $type = $node->getAttribute('itemtype');
            // itemtype peut être une URL schema.org -> garder le dernier segment
            $slash = strrpos($type, '/');
            if ($slash !== false) $type = substr($type, $slash+1);
            $micro[] = ['@type'=>$type, '@context'=>'https://schema.org'];
        }
        foreach ($xp->query('//*[@typeof]') as $node){
            $type = $node->getAttribute('typeof');
            if (strpos($type, ':') !== false) $type = substr($type, strrpos($type, ':')+1);
            $rdfa[] = ['@type'=>$type, '@context'=>'https://schema.org'];
        }
    }
    libxml_clear_errors();
    return [$jsonld, $micro, $rdfa];
}

function normalize_structured_data(array $items, $pageUrl){
    $out = [];
    foreach ($items as $it){
        if (!is_array($it)) continue;
        if (!isset($it['@type']) && isset($it['type'])) $it['@type'] = $it['type'];
        if (!isset($it['@context'])) $it['@context'] = 'https://schema.org';
        $fields = ['url','logo','image','@id'];
        foreach ($fields as $f){
            if (!empty($it[$f]) && is_string($it[$f]) && strpos($it[$f],'http')!==0){
                $it[$f] = resolve_url($pageUrl, $it[$f]);
            }
        }
        $out[] = $it;
    }
    return $out;
}

function resolve_url($base, $rel){
    if (!$rel) return $rel;
    if (preg_match('#^https?://#i', $rel)) return $rel;
    $base = rtrim($base,'/');
    if ($rel[0] === '/') {
        if (preg_match('#^(https?://[^/]+)#',$base,$m)) return $m[1].$rel;
        return $base.$rel;
    }
    return $base.'/'.ltrim($rel,'/');
}

// ==============================
// Validation par type (profil minimal viable)
// ==============================
function validate_schema_item(array $it, $siteBase, $testLogoSize=false){
    $type = $it['@type'] ?? 'Unknown';
    if (is_array($type)) $type = $type[0];
    $issues = [];
    $status = 'OK';

    $req = function($cond, $msg) use (&$issues, &$status){ if (!$cond){ $issues[]=$msg; if ($status!=='CRITIQUE') $status='ALERTE'; } };
    $rec = function($cond, $msg) use (&$issues){ if (!$cond){ $issues[]=$msg; } };

    switch ($type){
        case 'Organization':
        case 'LocalBusiness':
            $req(!empty($it['name']), 'name requis');
            $req(!empty($it['url']), 'url requise');
            if (!empty($it['url'])) $rec(stripos($it['url'], $siteBase)===0, 'url différente du domaine');
            if (!empty($it['logo'])){
                $req(is_string($it['logo']) && preg_match('#^https?://#',$it['logo']), 'logo doit être une URL absolue');
                if ($testLogoSize && is_string($it['logo']) && preg_match('#^https?://#',$it['logo'])){
                    $sz = fetch_image_size($it['logo']);
                    if ($sz && ($sz[0] < 112 || $sz[1] < 112)) $issues[] = 'logo < 112×112 recommandé par Google';
                }
            } else {
                $issues[] = 'logo recommandé';
            }
            if ($type==='LocalBusiness'){
                $addr = $it['address'] ?? [];
                $req(!empty($addr['streetAddress']) && !empty($addr['postalCode']) && !empty($addr['addressLocality']), 'address incomplet (street/postal/locality)');
                $rec(!empty($it['telephone']), 'telephone recommandé');
            }
            break;
        case 'WebSite':
            $rec(!empty($it['potentialAction']), 'SearchAction recommandé si recherche interne');
            break;
        case 'BreadcrumbList':
            $itemList = $it['itemListElement'] ?? [];
            $req(is_array($itemList) && count($itemList)>=2, 'Au moins 2 éléments breadcrumb requis');
            break;
        case 'Article':
        case 'NewsArticle':
        case 'BlogPosting':
            $req(!empty($it['headline']), 'headline requis');
            $req(!empty($it['datePublished']), 'datePublished requise');
            $req(!empty($it['author']), 'author requis');
            $rec(!empty($it['image']), 'image recommandée');
            break;
        case 'Product':
            $req(!empty($it['name']), 'name requis');
            $offers = $it['offers'] ?? [];
            if (isset($offers['@type']) || isset($offers['price'])){ $offers = [$offers]; }
            $hasPrice=false; $hasCurr=false;
            foreach ((array)$offers as $of){ if (!empty($of['price'])) $hasPrice=true; if (!empty($of['priceCurrency'])) $hasCurr=true; }
            $req($hasPrice, 'offers.price requis');
            $req($hasCurr, 'offers.priceCurrency requis');
            $rec(!empty($it['sku']), 'sku recommandé');
            $rec(!empty($it['brand']), 'brand recommandé');
            break;
        case 'FAQPage':
            $main = $it['mainEntity'] ?? [];
            $req(is_array($main) && count($main)>=1, 'mainEntity (questions) requis');
            break;
        default:
            $status = 'INFO';
            $issues[] = 'Type non profilé (contrôles légers)';
            break;
    }
    if ($status==='ALERTE' && empty($issues)) $status='OK';
    return ['status'=>$status,'issues'=>$issues];
}

function fetch_image_size($url){
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>true, CURLOPT_TIMEOUT=>6]);
    $bin = curl_exec($ch); curl_close($ch);
    if (!$bin) return null;
    if (function_exists('getimagesizefromstring')) return @getimagesizefromstring($bin);
    return null;
}

// ==============================
// Corrélations globales (minimum viable)
// ==============================
function correlate_global_inconsistencies(array $rows){
    $orgs = [];
    foreach ($rows as $r){ if ($r['type']==='Organization' || $r['type']==='LocalBusiness'){ $orgs[]=$r; } }
    $warn = [];
    if (count($orgs) >= 2){
        $warn[] = 'Plusieurs Organization/LocalBusiness détectés sur différentes pages — vérifier les doublons ou conflits de plugins SEO.';
    }
    return $warn;
}

// ==============================
// Rendu HTML
// ==============================

function render_results_table($rows, $global, $stats){
    echo '<div class="card"><h2 style="margin:0 0 8px 0">Synthèse</h2>';
    echo '<div class="kpi">';
    echo '<div><div class="muted">Pages scannées</div><div>'.h((string)$stats['pages']).'</div></div>';
    echo '<div><div class="muted">Blocs détectés</div><div>'.h((string)$stats['items']).'</div></div>';
    echo '<div><div class="muted">OK</div><div>'.badge((string)$stats['ok'],'OK').'</div></div>';
    echo '<div><div class="muted">Infos</div><div>'.badge((string)$stats['info'],'INFO').'</div></div>';
    echo '<div><div class="muted">Alertes</div><div>'.badge((string)$stats['warn'],'ALERTE').'</div></div>';
    echo '<div><div class="muted">Critiques</div><div>'.badge((string)$stats['crit'],'CRITIQUE').'</div></div>';
    echo '</div>'; // <-- ferme .kpi

    if ($global){
        echo '<div class="card" style="margin-top:12px">';
        echo '<h3 style="margin:0 0 8px 0">Incohérences globales possibles</h3><ul>';
        foreach ($global as $g){ echo '<li>'.h($g).'</li>'; }
        echo '</ul></div>';
    }
    echo '</div>'; // ferme la card "Synthèse"

    echo '<div class="card">';
    echo '<h2 style="margin:0 0 8px 0">Détails par page &amp; type</h2>';
    echo '<div class="small muted" style="margin-bottom:8px">Chaque ligne = un bloc de données structurées détecté.</div>';

    // --- Filtres rapides
    echo '<div class="small muted" style="margin:8px 0 6px">Filtres rapides :</div>';
    echo '<div id="status-filters" style="margin-bottom:10px;display:flex;gap:6px;flex-wrap:wrap">';
    $btnStyle = 'style="background:#0b1220;border:1px solid #1f2937;border-radius:10px;padding:6px 10px;color:#e2e8f0;cursor:pointer"';
    echo '<button '.$btnStyle.' data-filter="ALL" class="is-active">Tout</button>';
    echo '<button '.$btnStyle.' data-filter="OK">OK</button>';
    echo '<button '.$btnStyle.' data-filter="INFO">Infos</button>';
    echo '<button '.$btnStyle.' data-filter="ALERTE">Alertes</button>';
    echo '<button '.$btnStyle.' data-filter="CRITIQUE">Critiques</button>';
    echo '</div>';

    echo '<table id="schema-table"><thead><tr><th style="width:28%">URL</th><th style="width:16%">Type</th><th style="width:14%">Statut</th><th>Points relevés</th></tr></thead><tbody>';

    foreach ($rows as $r){
        $status = $r['status'];
        echo '<tr data-status="'.h($status).'">';
        echo '<td><div class="small"><a href="'.h($r['url']).'" target="_blank" rel="noopener">'.h($r['url']).'</a></div><details><summary class="muted small">extrait</summary><div class="mono">'.h($r['sample']).'</div></details></td>';
        echo '<td>'.h($r['type']).'</td>';
        echo '<td>'.badge($status, $status).'</td>';
        echo '<td><ul style="margin:0;padding-left:18px">';
        foreach ($r['issues'] as $i){ echo '<li>'.h($i).'</li>'; }
        echo '</ul></td>';
        echo '</tr>';
    }
    echo '</tbody></table></div>';

    // --- JS de filtrage
    echo <<<JS
<script>
(function(){
  var btns = document.querySelectorAll('#status-filters button');
  var rows = document.querySelectorAll('#schema-table tbody tr');
  function setActive(btn){
    btns.forEach(function(b){ b.classList.remove('is-active'); b.style.outline='none'; });
    btn.classList.add('is-active');
    btn.style.outline='2px solid #1f2937';
  }
  function applyFilter(f){
    rows.forEach(function(tr){
      if(f === 'ALL'){ tr.style.display=''; return; }
      var st = (tr.getAttribute('data-status')||'').trim();
      tr.style.display = (st === f) ? '' : 'none';
    });
  }
  btns.forEach(function(btn){
    btn.addEventListener('click', function(){
      setActive(btn);
      applyFilter(btn.getAttribute('data-filter'));
    });
  });
})();
</script>
JS;
}
?>
