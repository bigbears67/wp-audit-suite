<?php declare(strict_types=1);
require __DIR__ . '/audit_config.php';
$key = urlencode($_GET['key'] ?? '');
$base = htmlspecialchars(shortPath($ROOT));
header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Audit — Modules</title>
<style>
:root{--bg:#0f172a;--card:#111827;--b:#1f2937;--muted:#94a3b8}
body{background:var(--bg);color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:0;padding:24px}
h1{margin:0 0 12px} .card{background:#111827;border:1px solid var(--b);border-radius:12px;padding:16px;margin:14px 0}
a.btn{display:inline-block;background:#0b1220;border:1px solid var(--b);border-radius:10px;padding:10px 14px;color:#e2e8f0;text-decoration:none;margin:6px 6px 0 0}
small{color:var(--muted)}
</style></head><body>
<h1>WP Audit — Modules</h1>
<div class="card">
  <div>Racine: <?= $base ?> — WP: <?= $WP_LOADED ? 'oui' : 'non' ?> — <?= esc(date('Y-m-d H:i:s')) ?></div>
  <p><small>Astuce: ajoute <code>&max=1000</code> ou <code>&format=json</code> si besoin.</small></p>
  <p>
    <a class="btn" href="mod_headers.php?key=<?=$key?>">En-têtes thèmes/plugins</a>
    <a class="btn" href="mod_files.php?key=<?=$key?>&base=wp-content/plugins">Scan fichiers — plugins</a>
    <a class="btn" href="mod_files.php?key=<?=$key?>&base=wp-content/themes">Scan fichiers — thèmes</a>
    <a class="btn" href="mod_uploads.php?key=<?=$key?>">Uploads (PHP & images)</a>
    <a class="btn" href="mod_config.php?key=<?=$key?>">.htaccess / .user.ini</a>
    <a class="btn" href="mod_db.php?key=<?=$key?>">Base de données</a>
  </p>
</div>
</body></html>
