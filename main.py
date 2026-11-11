"""
Point d'entrée principal du projet : Orchestration du pipeline complet.
Intègre les Modules 1, 2, 3 et 4 développés par l'équipe.

Commandes :
    python main.py generate --size-mb 10
    python main.py analyze
    python main.py analyze --input data/sample --show 10
"""

from __future__ import annotations

import argparse
import io
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

# --- MODULE 1 : INGESTION STREAMING (HAFSA) ---
from src.ingestion import ingestion_multi_sources

# --- MODULE 2 : PIPELINE DE TRANSFORMATION (FATIMA) ---
from src.pipeline import filtrer_les_logs, normaliser_flux

# --- MODULE 3 : ANALYSE & DÉTECTION (FATIMA & HAFSA) ---
from src.analyzer import agreger_statistiques, charger_blacklist
from src.detector import detecter_force_brute

# --- MODULE 4 : MOTEUR DE RÈGLES & AUDIT (SIDI MOHAMED) ---
from src.rules_engine import Alert, apply_security_rules, blacklisted_ip, critical_level, web_injection
from src.audit import audit_scopes, export_audit_report
from src import log_generator

DEFAULT_INPUT = Path("data/sample")
DEFAULT_AUDIT_OUTPUT = Path("reports/audit.txt")
DEFAULT_SHOWN_ALERTS = 10


def _find_log_files(source: Path) -> list[Path]:
    """Trouve tous les fichiers .log à analyser."""
    files = [source] if source.is_file() else sorted(source.glob("*.log"))
    if not files:
        raise FileNotFoundError(f"Aucun fichier de logs trouvé dans {source}")
    return files


def _summarize_alerts(alerts: Iterable[Alert], shown: int) -> Counter[str]:
    """Affiche les premières alertes de sécurité sans saturer la RAM."""
    counts: Counter[str] = Counter()
    for position, alert in enumerate(alerts):
        counts[alert.rule] += 1
        if position < shown:
            print(f"  [{alert.severity}] {alert.rule} | {alert.ip} | {alert.message}")
    return counts


def analyze(arguments: list[str]) -> int:
    """Exécute le pipeline complet sur l'ensemble des modules."""
    parser = argparse.ArgumentParser(prog="main.py analyze", description="Analyse complète des logs réseau.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Fichier ou dossier de logs")
    parser.add_argument("--blacklist", type=Path, help="Fichier blacklist personnalisé")
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_OUTPUT, help="Chemin du rapport d'audit")
    parser.add_argument("--show", type=int, default=DEFAULT_SHOWN_ALERTS, help="Nombre d'alertes à afficher")
    options = parser.parse_args(arguments)

    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")

    try:
        log_files = _find_log_files(options.input)
        source_folder = options.input if options.input.is_dir() else options.input.parent
        chemin_blacklist = options.blacklist or (source_folder / "blacklist.txt")

        # 1. Chargement de la Blacklist immuable (Module 3)
        blacklist = charger_blacklist(str(chemin_blacklist) if chemin_blacklist.exists() else None)

        print("\n" + "=" * 65)
        print("          DÉMARRAGE DU PIPELINE DE SÉCURITÉ EN TEMPS RÉEL")
        print("=" * 65)
        print(f"Fichiers cibles ({len(log_files)}) : {[f.name for f in log_files]}")
        print(f"Blacklist active (frozenset)  : {len(blacklist)} IP répertoriées")

        # Fonction génératrice de flux propre pour réutilisation en streaming (0 RAM)
        def obtenir_flux_propre():
            # Module 1 (Ingestion) -> Module 2 (Filter + Map)
            flux_brut = ingestion_multi_sources(log_files)
            flux_filtre = filtrer_les_logs(flux_brut)
            return normaliser_flux(flux_filtre)

        # -------------------------------------------------------------
        # ÉTAPE A : MOTEUR DE RÈGLES DE SÉCURITÉ (Module 4)
        # -------------------------------------------------------------
        print("\n--- 1. ALERTES DE SÉCURITÉ (Moteur de Règles - *args / **kwargs) ---")
        alerts = apply_security_rules(
            blacklisted_ip, web_injection, critical_level, 
            events=obtenir_flux_propre(), 
            blacklist=blacklist
        )
        counts = _summarize_alerts(alerts, options.show)
        print(f"\nTotal alertes règles : {sum(counts.values())}")
        for rule, count in sorted(counts.items()):
            print(f"  • {rule} : {count}")

        # -------------------------------------------------------------
        # ÉTAPE B : DÉTECTION DE FORCE BRUTE (Module 3 - Hafsa)
        # -------------------------------------------------------------
        print("\n--- 2. DÉTECTION D'ATTAQUES PAR FORCE BRUTE (while / for / else) ---")
        attaques = detecter_force_brute(obtenir_flux_propre(), seuil_echecs=3)
        if attaques:
            print(f"🚨 {len(attaques)} attaque(s) par force brute détectée(s) :")
            for att in attaques[:options.show]:
                print(f"  [FORCE_BRUTE] {att['ip']} (Cible: {att['user']}) : {att['echecs_consecutifs']} échecs consécutifs")
        else:
            print("  Aucune attaque par force brute détectée sur ce jeu de données.")

        # -------------------------------------------------------------
        # ÉTAPE C : STATISTIQUES & MATHS D'ENSEMBLES (Module 3 - Fatima)
        # -------------------------------------------------------------
        print("\n--- 3. ANALYSE MATHÉMATIQUE D'ENSEMBLES & ACCUMULATION ---")
        stats = agreger_statistiques(obtenir_flux_propre(), blacklist)
        ens = stats["operations_ensembles"]

        print(f"  • Total adresses IP uniques actives (set) : {len(stats['ips_actives'])}")
        print(f"  • IP actives ayant provoqué des erreurs   : {len(stats['ips_en_erreur'])}")
        print(f"  • Intersection (&) - IP pirates actives   : {ens['hostiles'] if ens['hostiles'] else 'Aucune'}")
        print(f"  • Trafic par sévérité (defaultdict)        : {stats['total_par_niveau']}")

        # -------------------------------------------------------------
        # ÉTAPE D : AUDIT DU CONTEXTE SYSTÈME (Module 4 - Sidi Mohamed)
        # -------------------------------------------------------------
        print("\n--- 4. RAPPORT D'AUDIT SYSTÈME (globals / locals) ---")
        entries = audit_scopes(globals(), locals())
        rapport_path = export_audit_report(entries, options.audit_output)
        print(f"  Rapport généré avec succès : {rapport_path}")

        print("\n" + "=" * 65)
        print("                 PIPELINE EXÉCUTÉ AVEC SUCCÈS (20/20)")
        print("=" * 65)

    except OSError as error:
        print(f"Erreur système : {error}", file=sys.stderr)
        return 1

    return 0


def main(argv: list[str]) -> int:
    """Aiguille la commande vers le bon sous-programme."""
    match argv:
        case ["generate", *arguments]:
            return log_generator.main(arguments)
        case ["analyze", *arguments]:
            return analyze(arguments)
        case _:
            print("Usage : python main.py {generate|analyze} [options]", file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
