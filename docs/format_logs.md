# Format des logs et dictionnaire commun

Ce document est le contrat entre les modules. Toute modification passe par une pull request relue par les trois membres.

## Générer les données

```bash
python main.py generate --size-gb 12 --output data/raw
```

Avec la même graine (`--seed`, 42 par défaut) et la même version de Python, tout le monde obtient les mêmes fichiers.

| Fichier | Contenu |
|---|---|
| `app-0001.log`, `app-0002.log`, ... | Logs, découpés par taille (256 Mio par défaut) |
| `blacklist.txt` | Une IP par ligne, à charger dans un `frozenset` |
| `ground_truth.jsonl` | Attaques injectées, pour mesurer le détecteur |

`data/sample/` contient un échantillon de 2 Mio versionné, à utiliser pendant le développement.

## Les quatre formats de ligne

Lire les fichiers en binaire ou avec `errors="replace"` : certaines lignes contiennent des octets invalides.

### Ligne standard

```text
2026-10-01T00:00:12.345Z | ERROR | 192.168.1.10:443/TCP | u01042 | web | HTTP_REQUEST | {"method":"GET","path":"/","status":500,"bytes":120,"ms":34}
```

Champs dans l'ordre : horodatage, niveau, `ip:port/protocole`, utilisateur, catégorie, événement, payload (JSON ou texte).

### Dictionnaire JSON

```text
{"timestamp":"2026-10-01T00:00:12.345Z","level":"INFO","ip":"192.168.1.10","port":22,"protocol":"TCP","user":"u01042","category":"auth","event":"AUTH_SUCCESS","payload":{"method":"ssh"}}
```

### Tuple de connexion

```text
CONN 2026-10-01T00:00:12.345Z 192.168.1.10 22 TCP CONN_BLOCKED
```

Ce format ne donne ni le niveau, ni l'utilisateur, ni le payload.

### Chaîne brute

```text
kernel: eth0 link up 1000Mbps
```

Texte libre, sans horodatage ni IP.

## Le dictionnaire commun

Sortie de `pipeline.py` et entrée de `analyzer.py` et `detector.py` :

| Clé | Type | Remarque |
|---|---|---|
| `timestamp` | `datetime \| None` | En UTC ; `None` pour une chaîne brute |
| `level` | `str \| None` | `INFO`, `WARNING`, `ERROR` ou `CRITICAL` |
| `connection` | `tuple[str, int, str] \| None` | `(ip, port, protocole)`, protocole en majuscules |
| `ip` | `str \| None` | Identique à `connection[0]` |
| `user` | `str \| None` | En minuscules ; `None` si absent |
| `category` | `str \| None` | `web`, `auth`, `database`, `firewall`, `system`, `app` |
| `event` | `str \| None` | Par exemple `AUTH_FAILED` |
| `payload` | `dict \| str \| None` | `dict` si le JSON est valide, sinon le texte d'origine |
| `format` | `str` | `standard`, `json`, `connection` ou `raw` |

## Ce que le nettoyage doit traiter

### À corriger

| Défaut | Exemple | Résultat attendu |
|---|---|---|
| Casse ou alias du niveau | `error`, `Err`, `WARN`, `CRIT` | `ERROR`, `WARNING`, `CRITICAL` |
| Espaces et tabulations | `  ERROR\t` | `ERROR` |
| Utilisateur en majuscules | `U01042` | `u01042` |
| Utilisateur absent | `-`, `NULL`, `N/A`, `none` | `None` |
| Protocole en minuscules | `tcp` | `TCP` |
| Date au format espace | `2026-10-01 00:00:12.345` | `datetime` UTC |
| Date française | `01/10/2026 00:00:12` | `datetime` UTC, jour en premier |
| IP avec zéros | `192.168.001.010` | `192.168.1.10` |
| Espaces en début ou fin de ligne | `  CONN ...  ` | Ligne sans ces espaces |
| Payload JSON cassé | `{"method":"GET","pa` | Ligne gardée, payload en `str` |

### À rejeter ou à dédoublonner

| Défaut | Exemple |
|---|---|
| Ligne vide ou blanche | |
| Commentaire ou bannière | `# maintenance...`, `---- log rotated at ... ----` |
| Ligne tronquée ou champ manquant | Moins de 7 champs |
| IP invalide | `999.10.2.300`, `unknown`, `10.0.0` |
| Port invalide | `70000`, `-1`, `abc` |
| Niveau inconnu | `VERBOSE`, `???`, vide |
| Date invalide | `2026-13-45T25:61:00.000Z`, `hier` |
| Octets invalides | `\xff\xfe\x80` dans la ligne |
| Bruit | `#@!#@!#@!...` |
| Doublon consécutif | Même ligne deux fois de suite : n'en garder qu'une |

Comptez les rejets par type de défaut : ces chiffres serviront au rapport.

## Les attaques injectées

Chaque ligne de `ground_truth.jsonl` décrit une attaque ; `events` donne son nombre de lignes. Si `complete` vaut `false`, l'attaque a été coupée par la fin de la génération.

| `kind` | Signature dans les logs | À détecter ? |
|---|---|---|
| `brute_force` | 5 à 30 `AUTH_FAILED` de la même IP, suivis parfois d'un `AUTH_SUCCESS` (`details.succeeded`) | Oui |
| `mistype_decoy` | 2 ou 3 `AUTH_FAILED`, puis `AUTH_SUCCESS` | Non : faux positif à éviter |
| `port_scan` | 20 à 100 ports successifs en `CONN_BLOCKED` depuis la même IP | Oui |
| `dos_burst` | 100 à 400 requêtes de la même IP sur le même chemin | Oui |
| `web_injection` | 3 à 10 requêtes avec injection SQL ou traversée de chemin dans `path` | Oui |

Les attaques sont entrelacées avec le trafic normal : pour détecter des échecs consécutifs, il faut suivre chaque IP séparément.

Environ 60 % des IP attaquantes sont dans la blacklist. Elle contient aussi 200 IP jamais actives et 5 IP de clients normaux, ce qui rend intéressantes les opérations `|`, `&`, `-` et `^`.
