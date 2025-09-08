<?php declare(strict_types=1);
require __DIR__ . '/audit_config.php';

// Définition des modules disponibles
$available_modules = [
    'mod_config.php' => [
        'title' => 'Configuration',
        'desc' => 'Scan des fichiers .htaccess, .user.ini et configurations sensibles.',
        'params' => '&uploads_recommend=1'
    ],
    'mod_db.php' => [
        'title' => 'Base de Données',
        'desc' => 'Analyse des tables, options autoload, admins et charges suspectes.',
        'params' => '&recommend=1&links=1'
    ],
    'mod_files.php' => [
        'title' => 'Fichiers (Plugins)',
        'desc' => 'Recherche de motifs dangereux dans les fichiers PHP des plugins.',
        'params' => '&base=wp-content/plugins'
    ],
    'mod_uploads.php' => [
        'title' => 'Uploads',
        'desc' => 'Détection de PHP, images piégées et SVG dangereux dans les uploads.',
        'params' => ''
    ],
    'mod_headers.php' => [
        'title' => 'En-têtes',
        'desc' => 'Vérification des headers des thèmes et plugins.',
        'params' => ''
    ],
];

$key = $_GET['key'] ?? '';
$is_scan_run = false;
$results = [];
$kpi_summary = [];

// Exécute un module via une requête cURL locale
function run_module_scan(string $module_file, string $key, string $extra_params = ''): ?array {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = dirname($_SERVER['SCRIPT_NAME']);
    $url = sprintf('%s://%s%s/%s?key=%s&format=json%s', $scheme, $host, rtrim($path, '/'), $module_file, urlencode($key), $extra_params);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 300, // 5 minutes max par module
        CURLOPT_SSL_VERIFYPEER => false, // Pour les environnements locaux
        CURLOPT_SSL_VERIFYHOST => false,
    ]);
    $response = curl_exec($ch);
    curl_close($ch);

    return $response ? json_decode($response, true) : null;
}

// Si le formulaire est soumis, lancer les scans
if (!empty($_POST['modules']) && is_array($_POST['modules'])) {
    $is_scan_run = true;
    $selected_modules = $_POST['modules'];

    foreach ($selected_modules as $module_file) {
        if (!isset($available_modules[$module_file])) continue;

        $module_data = run_module_scan($module_file, $key, $available_modules[$module_file]['params']);
        
        $crit_count = 0;
        $alert_count = 0;

        if ($module_data && !empty($module_data['rows'])) {
            foreach ($module_data['rows'] as $row) {
                if ($row['severity'] === 'CRITIQUE') {
                    $crit_count++;
                    $results[] = array_merge($row, ['module' => $module_file]);
                } elseif ($row['severity'] === 'ALERTE') {
                    $alert_count++;
                    $results[] = array_merge($row, ['module' => $module_file]);
                }
            }
        }
        $kpi_summary[$module_file] = [
            'title' => $available_modules[$module_file]['title'],
            'total' => $module_data['count'] ?? 0,
            'crit' => $crit_count,
            'alert' => $alert_count,
        ];
    }
    // Trier les résultats par sévérité
    usort($results, function ($a, $b) {
        $sev_map = ['CRITIQUE' => 3, 'ALERTE' => 2, 'INFO' => 1];
        return ($sev_map[$b['severity']] ?? 0) <=> ($sev_map[$a['severity']] ?? 0);
    });
}

// Calcul du score de santé global
function calculate_health_score(array $kpi_summary): array {
    $total_crit = 0;
    $total_alert = 0;
    foreach ($kpi_summary as $kpi) {
        $total_crit += $kpi['crit'];
        $total_alert += $kpi['alert'];
    }

    if ($total_crit > 2) return ['score' => 'D', 'color' => '#dc2626', 'message' => 'Actions critiques requises'];
    if ($total_crit > 0) return ['score' => 'C', 'color' => '#f59e0b', 'message' => 'Problèmes critiques détectés'];
    if ($total_alert > 5) return ['score' => 'B', 'color' => '#facc15', 'message' => 'Nombreuses alertes'];
    if ($total_alert > 0) return ['score' => 'A', 'color' => '#84cc16', 'message' => 'Quelques alertes mineures'];
    return ['score' => 'A+', 'color' => '#22c55e', 'message' => 'Excellent état'];
}

$health = $is_scan_run ? calculate_health_score($kpi_summary) : null;

?>
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Audit — Tableau de Bord</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--b:#334155;--muted:#94a3b8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--info:#60a5fa;--yellow:#facc15}
body{background:var(--bg);color:#e2e8f0;font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px}
h1,h2,h3{margin:0 0 12px;color:#fff} h1 small{color:var(--muted);font-weight:normal}
.card{background:var(--card);border:1px solid var(--b);border-radius:12px;padding:20px;margin:16px 0}
a{color:var(--info);text-decoration:none} a:hover{text-decoration:underline}
.btn{display:inline-block;background:#3b82f6;color:#fff;border-radius:10px;padding:12px 20px;text-decoration:none;border:none;font-size:16px;cursor:pointer;font-weight:bold}
.btn:hover{background:#2563eb}
.module-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.module-card{background:#0f172a;border:1px solid var(--b);border-radius:10px;padding:16px;display:flex;align-items:flex-start;gap:12px}
.module-card input{width:20px;height:20px;margin-top:2px}
.module-card label{font-weight:bold;color:#fff}
.module-card .desc{font-size:13px;color:var(--muted)}
.results-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.kpi{background:#0f172a;border-radius:10px;padding:16px;text-align:center}
.kpi .label{font-size:13px;color:var(--muted);margin-bottom:8px}
.kpi .value{font-size:24px;font-weight:bold;color:#fff}
.score-card .score{font-size:64px;font-weight:bold;line-height:1}
table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{padding:10px;border-bottom:1px solid var(--b);vertical-align:top;text-align:left}
th{background:#0f172a}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid}
.badge-warn{color:var(--warn);border-color:var(--warn)} .badge-bad{color:var(--bad);border-color:var(--bad)}
</style></head><body>

<h1>Tableau de Bord <small>v<?= esc(WPAUDIT_VERSION) ?></small></h1>

<div class="card">
  <h2>Lancer un nouvel audit global</h2>
  <form action="" method="post">
    <p>Sélectionnez les modules à exécuter. L'audit peut prendre plusieurs minutes.</p>
    <div class="module-grid">
        <?php foreach ($available_modules as $file => $details): ?>
        <div class="module-card">
            <input type="checkbox" name="modules[]" value="<?= esc($file) ?>" id="mod_<?= esc($file) ?>" checked>
            <div>
                <label for="mod_<?= esc($file) ?>"><?= esc($details['title']) ?></label>
                <div class="desc"><?= esc($details['desc']) ?></div>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
    <div style="margin-top:20px;">
        <button type="submit" class="btn">🚀 Lancer l'audit</button>
    </div>
  </form>
</div>

<?php if ($is_scan_run): ?>
<div class="card" id="results">
    <h2>Résultats de l'audit</h2>
    <div class="results-grid">
        <div class="kpi score-card" style="align-items:center;text-align:center;display:flex;flex-direction:column;justify-content:center">
            <div class="label">Score de Santé</div>
            <div id="health-score-value" class="score" style="color:<?= esc($health['color']) ?>;"><?= esc($health['score']) ?></div>
            <div id="health-score-message" style="color:<?= esc($health['color']) ?>;"><?= esc($health['message']) ?></div>
            <div style="margin-top:10px;">
                <button id="recalculate-btn" class="btn" style="background:var(--b);font-size:13px;padding:8px 12px;">Recalculer le score</button>
            </div>
        </div>
        <?php foreach ($kpi_summary as $file => $kpi): ?>
        <div class="kpi">
            <div class="label"><a href="<?= esc($file) ?>?key=<?= esc($key) ?><?= esc($available_modules[$file]['params']) ?>" target="_blank"><?= esc($kpi['title']) ?></a></div>
            <div class="value"><?= esc((string)$kpi['total']) ?> <span style="font-size:14px;color:var(--muted)">détails</span></div>
            <div>
                <span class="badge badge-bad"><?= esc((string)$kpi['crit']) ?> Critiques</span>
                <span class="badge badge-warn"><?= esc((string)$kpi['alert']) ?> Alertes</span>
            </div>
        </div>
        <?php endforeach; ?>
    </div>

    <h3 style="margin-top:24px;">Synthèse des points critiques et alertes</h3>
    <?php if (empty($results)): ?>
        <p style="color:var(--ok);">✅ Aucune alerte ou point critique détecté dans les modules sélectionnés. Excellent !</p>
    <?php else: ?>
        <table>
            <thead><tr>
                <th style="width:40px;">Ignorer</th>
                <th>Niveau</th>
                <th>Module</th>
                <th>Type</th>
                <th>Objet / Chemin</th>
                <th>Détail</th>
            </tr></thead>
            <tbody>
                <?php foreach ($results as $row): 
                    $lvl = $row['severity'];
                    $cls = $lvl==='CRITIQUE'?'badge-bad':'badge-warn';
                    $object = $row['path'] ?? ($row['object'] ?? 'N/A');
                ?>
                <tr>
                    <td style="text-align:center;">
                        <?php if ($lvl === 'CRITIQUE' || $lvl === 'ALERTE'): ?>
                            <input type="checkbox" class="ignore-checkbox" data-severity="<?= esc($lvl) ?>">
                        <?php endif; ?>
                    </td>
                    <td><span class="badge <?= $cls ?>"><?= esc($lvl) ?></span></td>
                    <td><a href="<?= esc($row['module']) ?>?key=<?= esc($key) ?><?= esc($available_modules[$row['module']]['params']) ?>" target="_blank"><?= esc($available_modules[$row['module']]['title']) ?></a></td>
                    <td><?= esc($row['type'] ?? ($row['pattern'] ?? 'N/A')) ?></td>
                    <td style="word-break:break-word;"><?= esc(shortPath($object)) ?></td>
                    <td><?= esc($row['detail'] ?? 'N/A') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
<?php endif; ?>

<div class="card">
  <div style="font-size:12px;color:var(--muted)">
    🔔 Rappel : WP Audit Suite est un outil d’audit <b>lecture seule</b>. Ne le laissez pas en production :
    <b>supprimez</b> les fichiers une fois l’audit terminé.
  </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const recalculateBtn = document.getElementById('recalculate-btn');
    if (!recalculateBtn) return;

    // Récupérer les totaux initiaux calculés par PHP
    const initialCrit = <?= $health ? array_sum(array_column($kpi_summary, 'crit')) : 0 ?>;
    const initialAlert = <?= $health ? array_sum(array_column($kpi_summary, 'alert')) : 0 ?>;

    const scoreValueEl = document.getElementById('health-score-value');
    const scoreMessageEl = document.getElementById('health-score-message');

    // La même logique de scoring que PHP, mais en JavaScript
    function getScore(critCount, alertCount) {
        if (critCount > 2) return { score: 'D', color: '#dc2626', message: 'Actions critiques requises' };
        if (critCount > 0) return { score: 'C', color: '#f59e0b', message: 'Problèmes critiques détectés' };
        if (alertCount > 5) return { score: 'B', color: '#facc15', message: 'Nombreuses alertes' };
        if (alertCount > 0) return { score: 'A', color: '#84cc16', message: 'Quelques alertes mineures' };
        return { score: 'A+', color: '#22c55e', message: 'Excellent état' };
    }

    recalculateBtn.addEventListener('click', function() {
        let ignoredCrit = 0;
        let ignoredAlert = 0;

        document.querySelectorAll('.ignore-checkbox:checked').forEach(function(checkbox) {
            if (checkbox.dataset.severity === 'CRITIQUE') {
                ignoredCrit++;
            } else if (checkbox.dataset.severity === 'ALERTE') {
                ignoredAlert++;
            }
        });

        const newCrit = initialCrit - ignoredCrit;
        const newAlert = initialAlert - ignoredAlert;

        const newHealth = getScore(newCrit, newAlert);

        scoreValueEl.textContent = newHealth.score;
        scoreValueEl.style.color = newHealth.color;
        scoreMessageEl.textContent = newHealth.message;
        scoreMessageEl.style.color = newHealth.color;
    });
});
</script>

</body></html>
