# Engine de traitement et d'analyse de flux de données sécurisé

Projet final Python (ING3) : plateforme CLI d'ingestion, de filtrage, de transformation
et d'analyse de journaux de logs volumineux.

## Branches

- `main` : code stable, prêt pour la démo.
- `develop` : branche d'intégration commune.
- `feature/<nom>` : une branche par tâche, créée depuis `develop` et fusionnée par pull request.

## Démarrer

```bash
git clone https://github.com/sidimohamed-arch/projet-python.git
cd projet-python
git switch develop
git switch -c feature/ma-tache
```

Les fichiers de logs de 10-15 Go ne sont pas versionnés : ils sont produits localement par le générateur.
