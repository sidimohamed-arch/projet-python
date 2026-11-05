"""Étudiant 3 : point d'entrée du projet, qui pilote l'ensemble du pipeline en ligne de commande.

Commandes disponibles :
    python main.py generate --size-mb 10
    python main.py analyze
    python main.py analyze --input data/raw --show 20

La lecture des logs est TEMPORAIRE : en attendant src/ingestion.py et src/pipeline.py (étudiant 1),
_read_events_temporary comprend seulement les lignes standard et JSON, sans le nettoyage complet.
L'analyse et la détection (src/analyzer.py et src/detector.py, étudiant 2) restent à brancher.
"""

# Annotations récentes, non évaluées à l'exécution.
from __future__ import annotations

# argparse : lit les options de la commande.
import argparse

# io : type du flux de sortie.
import io

# json : décode le JSON.
import json

# sys : sortie standard et code de fin.
import sys

# Counter : compte des occurrences.
from collections import Counter

# Types utilisés dans les signatures.
from collections.abc import Iterable, Iterator

# Path : chemin de fichier.
from pathlib import Path

# Générateur de logs (commande generate).
from src import log_generator

# Audit des variables de portée.
from src.audit import audit_scopes, export_audit_report

# Moteur et règles de sécurité.
from src.rules_engine import Alert, Event, apply_security_rules, blacklisted_ip, critical_level, web_injection

# Dossier analysé par défaut.
DEFAULT_INPUT = Path("data/sample")

# Rapport d'audit par défaut.
DEFAULT_AUDIT_OUTPUT = Path("reports/audit.txt")

# Nombre d'alertes affichées par défaut.
DEFAULT_SHOWN_ALERTS = 10


# Signature : str -> Event | None
def _parse_line_temporary(line: str) -> Event | None:
    """Transforme une ligne standard ou JSON en dictionnaire. À remplacer par src/pipeline.py.

    Args:
        line: La ligne de log à lire.

    Returns:
        Le log sous forme de dictionnaire, ou None si son format n'est pas pris en charge.
    """
    # Retire les espaces autour de la ligne.
    text = line.strip()
    # 6 découpes au plus : le payload peut contenir " | ".
    fields = [field.strip() for field in text.split(" | ", 6)]

    # Traitement selon la forme de la ligne.
    match fields:
        # Ligne standard : 7 champs.
        case [_, level, address, _, _, event, payload]:
            # Garde ce qui précède le ":".
            ip = address.split(":")[0]
        # Un champ commençant par "{" : ligne JSON.
        case [single] if single.startswith("{"):
            # Une ligne JSON peut être coupée.
            try:
                # Texte vers dictionnaire.
                data = json.loads(single)
            except ValueError:
                # Ligne illisible : ignorée.
                return None
            # Même format qu'une ligne standard.
            return {
                # L'adresse IP source.
                "ip": data.get("ip"),
                # Niveau en majuscules.
                "level": str(data.get("level")).upper(),
                # Le nom de l'événement.
                "event": data.get("event"),
                # Payload déjà décodé.
                "payload": data.get("payload"),
            }
        # Autre format : non pris en charge.
        case _:
            # None : ligne ignorée.
            return None

    # Le payload peut être du texte ou un JSON cassé.
    try:
        # Dictionnaire si le JSON est valide.
        decoded_payload: dict[str, object] | str = json.loads(payload)
    except ValueError:
        # Sinon, on garde le texte.
        decoded_payload = payload

    # Champs utilisés par les règles.
    return {"ip": ip, "level": level.upper(), "event": event, "payload": decoded_payload}


# Signature : Iterable[Path] -> Iterator[Event]
def _read_events_temporary(paths: Iterable[Path]) -> Iterator[Event]:
    """Lit plusieurs fichiers ligne par ligne. À remplacer par src/ingestion.py et src/pipeline.py.

    Args:
        paths: Les fichiers de logs à lire, dans l'ordre.

    Yields:
        Chaque log reconnu, sans jamais charger un fichier entier en mémoire.
    """
    # Un fichier après l'autre.
    for path in paths:
        # errors="replace" : tolère les octets invalides.
        with path.open(encoding="utf-8", errors="replace") as file:
            # Lit une ligne à chaque tour.
            for line in file:
                # Ligne vers dictionnaire.
                event = _parse_line_temporary(line)
                # None : on saute la ligne.
                if event is not None:
                    # Rend le log, puis attend la demande suivante.
                    yield event


# Signature : Path -> list[Path]
def _find_log_files(source: Path) -> list[Path]:
    """Trouve les fichiers de logs à analyser.

    Args:
        source: Un fichier de logs, ou un dossier qui en contient.

    Returns:
        Les fichiers à lire, triés par nom pour garder l'ordre des journaux.

    Raises:
        FileNotFoundError: Si la source n'existe pas ou ne contient aucun fichier .log.
    """
    # Fichier seul, ou tous les .log du dossier.
    files = [source] if source.is_file() else sorted(source.glob("*.log"))
    # Aucun fichier à lire.
    if not files:
        # Erreur affichée par analyze.
        raise FileNotFoundError(f"Aucun fichier de logs trouvé dans {source}")
    # Liste des fichiers à lire.
    return files


# Signature : Path -> frozenset[str]
def _load_blacklist(path: Path) -> frozenset[str]:
    """Charge la blacklist, avec une adresse IP par ligne.

    Args:
        path: Le chemin du fichier blacklist.txt.

    Returns:
        Les adresses IP de la blacklist.

    Raises:
        OSError: Si le fichier ne peut pas être lu.
    """
    # with ferme le fichier automatiquement.
    with path.open(encoding="utf-8") as file:
        # IP sans doublon, sans les lignes vides.
        return frozenset(line.strip() for line in file if line.strip())


# Signature : Iterable[Alert] x int -> Counter[str]
def _summarize_alerts(alerts: Iterable[Alert], shown: int) -> Counter[str]:
    """Affiche les premières alertes et compte toutes les autres, sans les garder en mémoire.

    Args:
        alerts: Le flux d'alertes produit par le moteur.
        shown: Le nombre d'alertes à afficher en détail.

    Returns:
        Le nombre d'alertes par règle.
    """
    # Un total par règle.
    counts: Counter[str] = Counter()
    # Numérote les alertes à partir de 0.
    for position, alert in enumerate(alerts):
        # Compte chaque alerte.
        counts[alert.rule] += 1
        # Affiche seulement les premières.
        if position < shown:
            # Gravité, règle, IP, puis message.
            print(f"[{alert.severity}] {alert.rule} | {alert.ip} | {alert.message}")
    # Renvoie les totaux.
    return counts


# Signature : list[str] -> int
def analyze(arguments: list[str]) -> int:
    """Exécute l'analyse complète et exporte le rapport d'audit.

    Args:
        arguments: Les options de la commande analyze.

    Returns:
        0 si l'analyse a réussi, 1 si un fichier n'a pas pu être lu ou écrit.
    """
    # Décrit les options acceptées.
    parser = argparse.ArgumentParser(prog="main.py analyze", description="Analyse des fichiers de logs.")
    # Fichier ou dossier à analyser.
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="fichier ou dossier de logs")
    # Fichier des IP interdites.
    parser.add_argument(
        "--blacklist", type=Path, help="fichier blacklist (par défaut, dans le dossier --input)"
    )
    # Fichier du rapport d'audit.
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_OUTPUT, help="rapport d'audit")
    # Nombre d'alertes à afficher.
    parser.add_argument("--show", type=int, default=DEFAULT_SHOWN_ALERTS, help="alertes à afficher")
    # Lit les options de la commande.
    options = parser.parse_args(arguments)

    # La console peut refuser certains caractères.
    if isinstance(sys.stdout, io.TextIOWrapper):
        # Affiche leur code au lieu de planter.
        sys.stdout.reconfigure(errors="backslashreplace")

    # Regroupe tous les accès aux fichiers.
    try:
        # Repère les fichiers à lire.
        log_files = _find_log_files(options.input)
        # Blacklist cherchée à côté des logs.
        source_folder = options.input if options.input.is_dir() else options.input.parent
        # Charge la blacklist.
        blacklist = _load_blacklist(options.blacklist or source_folder / "blacklist.txt")
        # Générateur : rien n'est encore lu.
        events = _read_events_temporary(log_files)
        # Règles dans *args, options dans **kwargs.
        alerts = apply_security_rules(
            blacklisted_ip, web_injection, critical_level, events=events, blacklist=blacklist
        )
        # Cette lecture déclenche le traitement.
        counts = _summarize_alerts(alerts, options.show)

        # Affiche le total général.
        print(f"\n{sum(counts.values())} alerte(s) sur {len(log_files)} fichier(s)")
        # Ordre d'affichage stable.
        for rule, count in sorted(counts.items()):
            # Total de chaque règle.
            print(f"  {rule} : {count}")

        # Audite ce module et cette fonction.
        entries = audit_scopes(globals(), locals())
        # Écrit le rapport et affiche son chemin.
        print(f"Rapport d'audit : {export_audit_report(entries, options.audit_output)}")
    except OSError as error:
        # stderr : sortie des erreurs.
        print(f"Erreur : {error}", file=sys.stderr)
        # Code 1 : échec.
        return 1

    # Code 0 : réussite.
    return 0


# Signature : list[str] -> int
def main(argv: list[str]) -> int:
    """Oriente la commande vers le module concerné.

    Args:
        argv: Les arguments de la ligne de commande, sans le nom du programme.

    Returns:
        Le code de fin du programme.
    """
    # Reconnaît la commande.
    match argv:
        # Commande generate.
        case ["generate", *arguments]:
            # Code de fin du générateur.
            return log_generator.main(arguments)
        # Commande analyze.
        case ["analyze", *arguments]:
            # Code de fin de l'analyse.
            return analyze(arguments)
        # Toute autre saisie est une erreur.
        case _:
            # Rappelle les commandes disponibles.
            print("Usage : python main.py {generate|analyze} [options]", file=sys.stderr)
            # Code 2 : erreur d'utilisation.
            return 2


# Seulement si le fichier est lancé directement.
if __name__ == "__main__":
    # Transmet le code de fin au système.
    sys.exit(main(sys.argv[1:]))
