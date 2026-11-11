"""Analyse des adresses IP et statistiques d'accès réseau."""

from collections import defaultdict

def charger_blacklist(fichier_blacklist=None):
    """Charge les adresses IP suspectes et renvoie un frozenset immuable."""
    ips = set()
    if fichier_blacklist:
        try:
            with open(fichier_blacklist, "r", encoding="utf-8") as file:
                for line in file:
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        ips.add(ip)
        except FileNotFoundError:
            pass

    if not ips:
        ips = {"198.51.100.23", "203.0.113.88", "185.220.101.5", "192.0.2.14"}

    return frozenset(ips)


def analyser_les_ensembles_ip(ips_actives, blacklist_ips):
    """Exécute les 4 opérations mathématiques obligatoires sur les ensembles."""
    return {
        "union": ips_actives | blacklist_ips,
        "hostiles": ips_actives & blacklist_ips,
        "saines": ips_actives - blacklist_ips,
        "divergentes": ips_actives ^ blacklist_ips,
    }


def agreger_statistiques(flux_de_logs, blacklist_ips):
    """Collecte les IP uniques, compte par niveau et utilisateur avec defaultdict."""
    ips_actives = set()
    ips_en_erreur = set()
    compteur_niveaux = defaultdict(int)
    compteur_utilisateurs = defaultdict(int)

    for log in flux_de_logs:
        ip = log.get("ip", "0.0.0.0")
        niveau = log.get("level", "INFO")
        user = log.get("user", "inconnu")

        ips_actives.add(ip)
        compteur_niveaux[niveau] += 1
        compteur_utilisateurs[user] += 1

        if niveau in {"ERROR", "CRITICAL"}:
            ips_en_erreur.add(ip)

    resultats_maths = analyser_les_ensembles_ip(ips_actives, blacklist_ips)

    return {
        "ips_actives": ips_actives,
        "ips_en_erreur": ips_en_erreur,
        "total_par_niveau": dict(compteur_niveaux),
        "total_par_utilisateur": dict(compteur_utilisateurs),
        "operations_ensembles": resultats_maths,
    }
