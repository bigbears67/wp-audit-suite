# WP Audit Suite

WP Audit Suite est une collection de modules PHP en **lecture seule** pour auditer un site WordPress.  
L’objectif : fournir un diagnostic clair et rapide sur la sécurité, les fichiers, la configuration et la base de données **sans aucune action destructive**.

---

## 🧩 Modules inclus

- **audit_index.php** — Tableau de bord central pour accéder aux audits.
- **mod_headers.php** — Vérifie les en-têtes de thèmes et plugins (headers manquants, code avant header, Update URI).
- **mod_files.php** — Recherche de patterns PHP suspects (`eval`, `assert`, `system`, `exec`, `base64_decode`, etc.) avec contexte.
- **mod_uploads.php** — Analyse du dossier `uploads/` (fichiers PHP interdits, index placeholder, extensions suspectes).
- **mod_config.php** — Vérifie les `.htaccess` : protection des répertoires, absence de `Options Indexes`, sécurité PHP dans `uploads`.
- **mod_db.php** — Audit de la base de données (tables volumineuses, autoload lourd, cron), avec un panneau de recommandations en option.

---

## 🚀 Installation

1. Télécharger la dernière release (ZIP) depuis [Releases](../../releases).  
2. Décompresser le dossier `wp-audit-suite/` à la racine de votre site WordPress.  
3. Copier `audit_config.sample.php` en `audit_config.php` et définir votre mot de passe (`AUDIT_KEY`).  
4. Accéder à l’interface :  
