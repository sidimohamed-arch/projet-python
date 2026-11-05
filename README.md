# Engine de traitement et d'analyse de flux de données sécurisé

Projet final Python (ING3) : plateforme CLI d'ingestion, de filtrage, de transformation
et d'analyse de journaux de logs volumineux.

## Branches

- `main` : code stable, prêt pour la démo.
- `develop` : branche de travail commune, sur laquelle on commite directement.

Il n'y a pas d'autre branche.

## Démarrer

```bash
git clone https://github.com/sidimohamed-arch/projet-python.git
cd projet-python
git switch develop
```

Les fichiers de logs de 10-15 Go ne sont pas versionnés : ils sont produits localement par le générateur.

## Installer l'environnement

Clonez le dépôt hors de OneDrive, puis, sous Windows :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Après chaque ajout de bibliothèque : `python -m pip freeze > requirements.txt`.

## Commandes utiles

```bash
python main.py generate --size-gb 12   # logs complets dans data/raw/
python -m pytest                       # tests
python -m ruff check .                 # PEP8
python -m ruff format .                # mise en forme
python -m mypy                         # typage
```

Le format des logs et le dictionnaire commun sont décrits dans [docs/format_logs.md](docs/format_logs.md).
