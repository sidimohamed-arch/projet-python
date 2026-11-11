"""Analyse des adresses IP et statistiques d'accès réseau."""

from collections import defaultdict

# 1. GESTION DE LA BLACKLIST ET DES ENSEMBLES D'IP (set / frozenset)

def charger_blacklist(fichier_blacklist=None):
    """
    Charge les adresses IP suspectes et renvoie un frozenset immuable.
    Garantit que la liste ne peut pas être modifiée pendant l'analyse.
    """
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

    # Liste de secours si aucune adresse n'a été chargée
    if not ips:
        ips = {"198.51.100.23", "203.0.113.88", "185.220.101.5", "192.0.2.14"}

    return frozenset(ips)


def analyser_les_ensembles_ip(ips_actives, blacklist_ips):
    """
    Exécute les 4 opérations mathématiques obligatoires sur les ensembles :
      - Union (|)
      - Intersection (&)
      - Différence (-)
      - Différence symétrique (^)
    """
    # 1. Union (|) : Totalité de toutes les adresses IP sans doublon
    toutes_les_ips = ips_actives | blacklist_ips

    # 2. Intersection (&) : IP actives présentes dans la blacklist
    ips_hostiles_detectees = ips_actives & blacklist_ips

    # 3. Différence (-) : IP actives absentes de la blacklist
    ips_saines = ips_actives - blacklist_ips

    # 4. Différence symétrique (^) : IP présentes dans un seul des deux ensembles
    ips_divergentes = ips_actives ^ blacklist_ips

    return {
        "union": toutes_les_ips,
        "hostiles": ips_hostiles_detectees,
        "saines": ips_saines,
        "divergentes": ips_divergentes,
    }



# 2. COMPTAGE DYNAMIQUE SANS CRASH (collections.defaultdict)


def agreger_statistiques(flux_de_logs, blacklist_ips):
    """
    Parcourt les logs pour :
      - Collecter les IP uniques (set)
      - Compter par niveau et par utilisateur sans KeyError (defaultdict)
      - Calculer les métriques de sécurité
    """
    ips_actives = set()
    ips_en_erreur = set()

    # defaultdict(int) prévient tout KeyError en initialisant à 0
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

    # Calcul des ensembles mathématiques
    resultats_maths = analyser_les_ensembles_ip(ips_actives, blacklist_ips)

    return {
        "ips_actives": ips_actives,
        "ips_en_erreur": ips_en_erreur,
        "total_par_niveau": dict(compteur_niveaux),
        "total_par_utilisateur": dict(compteur_utilisateurs),
        "operations_ensembles": resultats_maths,
    }


# ZONE DE TEST (Pour exécuter et voir les statistiques)

if __name__ == "__main__":
    print("=" * 60)
    print("      DEMONSTRATION DU MODULE ANALYZER (ENSEMBLES & STATS)")
    print("=" * 60)

    # 1. Chargement de la blacklist immuable
    blacklist = charger_blacklist()
    print(f"\n1. Blacklist immuable (frozenset) chargée : {len(blacklist)} adresses IP")
    print(f"   IPs hostiles de référence : {blacklist}")

    # 2. Simulation de logs arrivant du réseau
    faux_logs = [
        {"ip": "192.168.1.10", "level": "INFO", "user": "alice"},
        {"ip": "198.51.100.23", "level": "ERROR", "user": "root"},        # IP blacklistée !
        {"ip": "192.168.1.12", "level": "ERROR", "user": "fatima"},
        {"ip": "203.0.113.88", "level": "CRITICAL", "user": "admin"},     # IP blacklistée !
        {"ip": "192.168.1.10", "level": "INFO", "user": "alice"},
        {"ip": "192.168.1.55", "level": "WARNING", "user": "charlie"},
    ]

    print(f"\n2. Analyse d'un flux de {len(faux_logs)} logs...")
    stats = agreger_statistiques(faux_logs, blacklist)

    # 3. Affichage des opérations mathématiques sur ensembles
    ensembles = stats["operations_ensembles"]
    print("\n--- 3. OPERATIONS MATHEMATIQUES SUR ENSEMBLES ---")
    print(f"Total IP actives détectées (set) : {stats['ips_actives']}")
    print(f"IP ayant provoqué des erreurs   : {stats['ips_en_erreur']}")
    print(f"Union (|)                       : {len(ensembles['union'])} adresses au total")
    print(f"IP actives blacklistées (&)     : {ensembles['hostiles']}")
    print(f"IP actives non blacklistées (-) : {ensembles['saines']}")
    print(f"Différence symétrique (^)       : {len(ensembles['divergentes'])} adresses")

    # 4. Affichage des compteurs defaultdict
    print("\n--- 4. ACCUMULATION SANS ERREUR (defaultdict) ---")
    print(f"Nombre d'événements par niveau     : {stats['total_par_niveau']}")
    print(f"Nombre d'événements par utilisateur: {stats['total_par_utilisateur']}")

    print("\n" + "=" * 60)
    print("  TOUTES LES METRIQUES SONT CALCULEES AVEC SUCCES !")
    print("=" * 60)
