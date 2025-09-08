# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhère à la [Gestion Sémantique de Version](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-09-08
### Added
- **Tableau de Bord d'Audit Global (`audit_index.php`)** : Une nouvelle interface centrale pour lancer plusieurs modules simultanément, agréger leurs résultats et obtenir une vision d'ensemble.
- **Score de Santé Global** : Le tableau de bord affiche une note de santé (de A+ à D) pour une évaluation rapide de l'état de sécurité du site.
- **Fonctionnalité d'Ignorer les Alertes** : Ajout de cases à cocher dans le tableau de résultats pour marquer les faux positifs.
- **Recalcul du Score en Temps Réel** : Un bouton permet de mettre à jour le score de santé en excluant les alertes ignorées, sans recharger la page.
- **Scan des Domaines Externes** : Le module `mod_db.php` peut maintenant scanner la base de données à la recherche de liens sortants (activable avec `&links=1`).

### Changed
- **Refonte de l'Expérience Utilisateur** : Le projet passe d'une collection de scripts indépendants à une application web intégrée, centrée sur le tableau de bord.
- **Amélioration de la Navigation** : Remplacement des liens par un bouton "Précédent" utilisant l'historique du navigateur pour une navigation plus fluide entre les modules et le tableau de bord.

---

## [0.3.0] - 2025-09-08
### Added
- **mod_data.php** : audit des données structurées (JSON-LD, Microdata, RDFa).
  - Détecte : Organization/LocalBusiness, WebSite, BreadcrumbList, Article/BlogPosting, Product, FAQPage.
  - Vérifie les champs requis/recommandés (logo absolu, offers.price, etc.).
  - Normalisation des URLs relatives, support `@graph`.
- **Dashboard** : tuile “Données structurées (schema.org)” dans `audit_index.php`.
- **Filtres rapides** (OK/INFO/ALERTE/CRITIQUE) dans le tableau des résultats.

### Fixed
- Échappement/quoting de l’en-tête HTML (HEREDOC) pour éviter `Parse error` sur certaines versions de PHP.

### Notes
- 100% lecture seule — à **supprimer** du serveur après usage.