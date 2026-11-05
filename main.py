"""Étudiant 3 : point d'entrée du projet, qui pilote l'ensemble du pipeline en ligne de commande.

Commandes disponibles :
    python main.py generate --size-mb 10
    python main.py analyze
    python main.py analyze --input data/raw --show 20

La lecture des logs est TEMPORAIRE : en attendant src/ingestion.py et src/pipeline.py (étudiant 1),
_read_events_temporary comprend seulement les lignes standard et JSON, sans le nettoyage complet.
L'analyse et la détection (src/analyzer.py et src/detector.py, étudiant 2) restent à brancher.
"""

# Permet d'écrire les annotations récentes (ex : "Event | None") sans les évaluer à l'exécution.
from __future__ import annotations

# argparse : lit les options de la ligne de commande et génère l'aide --help.
import argparse

# io : fournit le type du flux de sortie, nécessaire pour configurer son traitement des erreurs.
import io

# json : décode les lignes et les payloads au format JSON.
import json

# sys : donne accès à la sortie standard, aux arguments et au code de fin du programme.
import sys

# Counter : compte des occurrences sans risque de KeyError.
from collections import Counter

# Iterable : tout ce qu'on peut parcourir avec for. Iterator : un flux lu à la demande.
from collections.abc import Iterable, Iterator

# Path : représente un chemin de fichier, quel que soit le système d'exploitation.
from pathlib import Path

# Le générateur de logs, utilisé par la commande generate.
from src import log_generator

# Les fonctions de l'audit des variables de portée.
from src.audit import audit_scopes, export_audit_report

# Le moteur et les règles de sécurité : les règles sont des fonctions passées en argument au moteur.
from src.rules_engine import Alert, Event, apply_security_rules, blacklisted_ip, critical_level, web_injection

# Dossier analysé par défaut : le jeu de données de test fourni avec le projet.
DEFAULT_INPUT = Path("data/sample")

# Fichier du rapport d'audit par défaut. Le dossier reports/ n'est pas versionné.
DEFAULT_AUDIT_OUTPUT = Path("reports/audit.txt")

# Nombre d'alertes affichées par défaut : un gros fichier peut en produire des millions.
DEFAULT_SHOWN_ALERTS = 10


# Signature : reçoit une ligne de log (str), renvoie un dictionnaire ou None si la ligne est ignorée.
def _parse_line_temporary(line: str) -> Event | None:
    """Transforme une ligne standard ou JSON en dictionnaire. À remplacer par src/pipeline.py.

    Args:
        line: La ligne de log à lire.

    Returns:
        Le log sous forme de dictionnaire, ou None si son format n'est pas pris en charge.
    """
    # On retire les espaces autour de la ligne avant de reconnaître son format.
    text = line.strip()
    # On découpe au plus 6 fois : un payload en texte peut contenir lui-même le séparateur.
    fields = [field.strip() for field in text.split(" | ", 6)]

    # match-case choisit le traitement selon la forme de la ligne découpée.
    match fields:
        # Une ligne standard contient exactement 7 champs : on ignore ceux qui ne servent pas ici.
        case [_, level, address, _, _, event, payload]:
            # L'adresse s'écrit "ip:port/protocole" : on garde ce qui précède le ":".
            ip = address.split(":")[0]
        # Un seul champ qui commence par "{" : c'est une ligne JSON.
        case [single] if single.startswith("{"):
            # try surveille le décodage, car une ligne JSON peut être coupée.
            try:
                # json.loads transforme le texte en dictionnaire.
                data = json.loads(single)
            except ValueError:
                # Une ligne JSON illisible est ignorée, sans arrêter l'analyse.
                return None
            # On reprend ces champs dans le même format que ceux d'une ligne standard.
            return {
                # L'adresse IP source.
                "ip": data.get("ip"),
                # Le niveau, mis en majuscules ; str() protège d'une valeur qui ne serait pas du texte.
                "level": str(data.get("level")).upper(),
                # Le nom de l'événement.
                "event": data.get("event"),
                # Le payload, déjà décodé avec le reste de la ligne.
                "payload": data.get("payload"),
            }
        # Tout autre format (tuple de connexion, chaîne brute...) n'est pas pris en charge ici.
        case _:
            # None indique à l'appelant d'ignorer cette ligne.
            return None

    # try surveille le décodage du payload, car il peut être du texte ou un JSON cassé.
    try:
        # Le payload devient un dictionnaire s'il contient du JSON valide.
        decoded_payload: dict[str, object] | str = json.loads(payload)
    except ValueError:
        # Sinon, on garde le texte d'origine, comme le prévoit docs/format_logs.md.
        decoded_payload = payload

    # On renvoie uniquement les champs utilisés par les règles actuelles.
    return {"ip": ip, "level": level.upper(), "event": event, "payload": decoded_payload}


# Signature : reçoit des chemins de fichiers, renvoie un flux de logs lu à la demande.
def _read_events_temporary(paths: Iterable[Path]) -> Iterator[Event]:
    """Lit plusieurs fichiers ligne par ligne. À remplacer par src/ingestion.py et src/pipeline.py.

    Args:
        paths: Les fichiers de logs à lire, dans l'ordre.

    Yields:
        Chaque log reconnu, sans jamais charger un fichier entier en mémoire.
    """
    # On traite les fichiers les uns après les autres.
    for path in paths:
        # errors="replace" : certaines lignes contiennent des octets invalides (voir docs/format_logs.md).
        with path.open(encoding="utf-8", errors="replace") as file:
            # Parcourir le fichier lit une seule ligne à chaque tour.
            for line in file:
                # On transforme la ligne en dictionnaire.
                event = _parse_line_temporary(line)
                # Une ligne non reconnue vaut None : on la saute.
                if event is not None:
                    # yield rend le log tout de suite, puis attend la demande suivante.
                    yield event


# Signature : reçoit un chemin de fichier ou de dossier, renvoie la liste triée des fichiers de logs.
def _find_log_files(source: Path) -> list[Path]:
    """Trouve les fichiers de logs à analyser.

    Args:
        source: Un fichier de logs, ou un dossier qui en contient.

    Returns:
        Les fichiers à lire, triés par nom pour garder l'ordre des journaux.

    Raises:
        FileNotFoundError: Si la source n'existe pas ou ne contient aucun fichier .log.
    """
    # Une source qui est un fichier est utilisée telle quelle ; sinon, on cherche les .log du dossier.
    files = [source] if source.is_file() else sorted(source.glob("*.log"))
    # Sans fichier à lire, l'analyse n'aurait aucun sens.
    if not files:
        # Cette erreur sera affichée proprement par la commande analyze.
        raise FileNotFoundError(f"Aucun fichier de logs trouvé dans {source}")
    # On renvoie la liste complète des fichiers à lire.
    return files


# Signature : reçoit le chemin de la blacklist, renvoie un ensemble immuable d'adresses IP.
def _load_blacklist(path: Path) -> frozenset[str]:
    """Charge la blacklist, avec une adresse IP par ligne.

    Args:
        path: Le chemin du fichier blacklist.txt.

    Returns:
        Les adresses IP de la blacklist.

    Raises:
        OSError: Si le fichier ne peut pas être lu.
    """
    # with ferme le fichier automatiquement, même en cas d'erreur.
    with path.open(encoding="utf-8") as file:
        # frozenset : immuable, et sa recherche reste quasi instantanée. Les lignes vides sont ignorées.
        return frozenset(line.strip() for line in file if line.strip())


# Signature : reçoit le flux d'alertes et le nombre à afficher, renvoie le total d'alertes par règle.
def _summarize_alerts(alerts: Iterable[Alert], shown: int) -> Counter[str]:
    """Affiche les premières alertes et compte toutes les autres, sans les garder en mémoire.

    Args:
        alerts: Le flux d'alertes produit par le moteur.
        shown: Le nombre d'alertes à afficher en détail.

    Returns:
        Le nombre d'alertes par règle.
    """
    # Ce compteur garde un seul nombre par règle, quelle que soit la quantité d'alertes.
    counts: Counter[str] = Counter()
    # enumerate numérote les alertes à partir de 0, au fur et à mesure de leur lecture.
    for position, alert in enumerate(alerts):
        # On compte chaque alerte, même celles qui ne sont pas affichées.
        counts[alert.rule] += 1
        # On affiche seulement les premières alertes.
        if position < shown:
            # L'alerte tient sur une ligne : gravité, règle, IP, puis message.
            print(f"[{alert.severity}] {alert.rule} | {alert.ip} | {alert.message}")
    # On renvoie les totaux à afficher dans le résumé.
    return counts


# Signature : reçoit les arguments de la commande, renvoie le code de fin du programme.
def analyze(arguments: list[str]) -> int:
    """Exécute l'analyse complète et exporte le rapport d'audit.

    Args:
        arguments: Les options de la commande analyze.

    Returns:
        0 si l'analyse a réussi, 1 si un fichier n'a pas pu être lu ou écrit.
    """
    # Le parseur décrit les options acceptées et génère le message d'aide.
    parser = argparse.ArgumentParser(prog="main.py analyze", description="Analyse des fichiers de logs.")
    # Option --input : le fichier ou le dossier à analyser.
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="fichier ou dossier de logs")
    # Option --blacklist : le fichier des IP interdites.
    parser.add_argument(
        "--blacklist", type=Path, help="fichier blacklist (par défaut, dans le dossier --input)"
    )
    # Option --audit-output : le fichier du rapport d'audit.
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_OUTPUT, help="rapport d'audit")
    # Option --show : le nombre d'alertes à afficher en détail.
    parser.add_argument("--show", type=int, default=DEFAULT_SHOWN_ALERTS, help="alertes à afficher")
    # parse_args lit les options ; en cas d'option invalide, argparse affiche l'erreur et quitte.
    options = parser.parse_args(arguments)

    # Une ligne de log peut contenir un caractère que la console Windows ne sait pas afficher.
    if isinstance(sys.stdout, io.TextIOWrapper):
        # backslashreplace affiche ce caractère sous forme de code au lieu de faire planter le programme.
        sys.stdout.reconfigure(errors="backslashreplace")

    # try regroupe tous les accès aux fichiers, y compris la lecture à la demande des logs.
    try:
        # On repère d'abord les fichiers à lire : une source absente donne ainsi le bon message d'erreur.
        log_files = _find_log_files(options.input)
        # Sans option --blacklist, on cherche le fichier à côté des logs.
        source_folder = options.input if options.input.is_dir() else options.input.parent
        # On charge la blacklist fournie, ou celle du dossier des logs.
        blacklist = _load_blacklist(options.blacklist or source_folder / "blacklist.txt")
        # Ce générateur ne lit rien pour l'instant : les logs seront lus à la demande.
        events = _read_events_temporary(log_files)
        # Les règles sont des fonctions passées dans *args ; events et blacklist arrivent dans **kwargs.
        alerts = apply_security_rules(
            blacklisted_ip, web_injection, critical_level, events=events, blacklist=blacklist
        )
        # C'est cette lecture des alertes qui déclenche réellement le traitement des logs.
        counts = _summarize_alerts(alerts, options.show)

        # Ligne de séparation entre le détail des alertes et le résumé.
        print(f"\n{sum(counts.values())} alerte(s) sur {len(log_files)} fichier(s)")
        # sorted() donne toujours le même ordre d'affichage.
        for rule, count in sorted(counts.items()):
            # On affiche le total de chaque règle ayant levé au moins une alerte.
            print(f"  {rule} : {count}")

        # globals() et locals() sont appelés ici, pour auditer ce module et cette fonction.
        entries = audit_scopes(globals(), locals())
        # On écrit le rapport et on affiche son emplacement.
        print(f"Rapport d'audit : {export_audit_report(entries, options.audit_output)}")
    except OSError as error:
        # stderr est la sortie réservée aux erreurs : elle reste séparée des résultats.
        print(f"Erreur : {error}", file=sys.stderr)
        # Un code différent de 0 signale l'échec au système.
        return 1

    # Le code 0 signale que tout s'est bien passé.
    return 0


# Signature : reçoit les arguments de la ligne de commande, renvoie le code de fin du programme.
def main(argv: list[str]) -> int:
    """Oriente la commande vers le module concerné.

    Args:
        argv: Les arguments de la ligne de commande, sans le nom du programme.

    Returns:
        Le code de fin du programme.
    """
    # match-case reconnaît la commande et récupère le reste des arguments dans une liste.
    match argv:
        # La commande generate est confiée au générateur de logs.
        case ["generate", *arguments]:
            # On renvoie le code de fin du générateur.
            return log_generator.main(arguments)
        # La commande analyze lance l'analyse.
        case ["analyze", *arguments]:
            # On renvoie le code de fin de l'analyse.
            return analyze(arguments)
        # Toute autre saisie est une erreur d'utilisation.
        case _:
            # Le message rappelle les commandes disponibles.
            print("Usage : python main.py {generate|analyze} [options]", file=sys.stderr)
            # Le code 2 est l'usage habituel pour une erreur de ligne de commande.
            return 2


# Ce bloc s'exécute seulement si le fichier est lancé directement, pas s'il est importé.
if __name__ == "__main__":
    # sys.argv[1:] retire le nom du programme ; sys.exit transmet le code de fin au système.
    sys.exit(main(sys.argv[1:]))
