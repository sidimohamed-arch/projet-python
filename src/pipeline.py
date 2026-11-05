"""Pipeline de transformation et de filtrage des logs réseau."""

def filtrer_les_logs(flux_de_logs):
    """Élimine les entrées vides et les logs mal formés."""
    
    # 1. Élimination des None et des textes vides :
    flux_sans_vide = filter(None, flux_de_logs)
    # 2. les niveaux acceptés :
    niveaux_valides = {"INFO", "WARNING", "ERROR", "CRITICAL"}
    
    # 3. Filtrage précis avec une fonction anonyme lambda :
    logs_propres = filter(
        lambda log: (
            isinstance(log, dict)
            and isinstance(log.get("level"), str)
            and log["level"].strip().upper() in niveaux_valides
            and isinstance(log.get("user"), str)
            and bool(log["user"].strip())
        ),
        flux_sans_vide

    )
    return logs_propres

def normaliser_un_log(log):
    """Nettoie un log individuel : casse, espaces et résumé f-string."""
    
    # 1. Nettoyage du pseudo et du niveau :
    pseudo_propre = str(log.get("user", "")).strip().lower()
    niveau_propre = str(log.get("level", "")).strip().upper()
    adresse_ip = log.get("ip", "0.0.0.0")
    # 2. Création d'une phrase de synthèse avec une f-string 
    resume = f"[{niveau_propre}] Connexion depuis {adresse_ip} par '{pseudo_propre}'"
    # 3. Création du dictionnaire final nettoyé :
    log_nettoye = dict(log)
    log_nettoye["user"] = pseudo_propre
    log_nettoye["level"] = niveau_propre
    log_nettoye["summary"] = resume
    return log_nettoye
def normaliser_flux(flux_de_logs):
    """Applique la normalisation à tout le flux grâce à map()."""
    return map(normaliser_un_log, flux_de_logs)


def router_le_log(donnee):
    """Examine la structure d'une donnée et l'oriente selon son format."""
    
    match donnee:
        # Cas 1 : une simple chaîne de texte brute :
        case str(texte):
            return f"ROUTAGE -> TEXTE BRUT : {texte}"
        # Cas 2 : un dictionnaire d'erreur contenant un sous-code :
        case {"level": "ERROR", "payload": {"code": code_erreur}}:
            return f"Erreur avec le code {code_erreur}"
        # Cas 3 : un incident CRITICAL avec un utilisateur :
        case {"level": "CRITICAL", "user": pseudo}:
            return f"ROUTAGE -> ALERTE CRITIQUE SUR : {pseudo}"
        # Cas 4 : un Tuple de connexion réseau (IP, Port, Protocole) :
        case (str(ip), int(port), str(proto)):
            return f"ROUTAGE -> TUPLE RESEAU : {ip}:{port}/{proto}"
        # Cas par défaut : Tout autre format non reconnu :
        case _:
            return "ROUTAGE -> FORMAT INCONNU"


        # =====================================================================
# ZONE D'EXECUTION ET DE TEST
# =====================================================================
if __name__ == "__main__":
    print("Test du filtrage et de la normalisation")
    # 1. Jeu de test avec des données sales et des erreurs :
    donnees_brutes = [
        None,
        {"level": "INFO", "user": "  Alice  ", "ip": "192.168.1.10"},
        {"level": "INTRUS", "user": "hacker", "ip": "10.0.0.99"},
        {"level": "ERROR", "user": "   ", "ip": "10.0.0.1"},
        {"level": "CRITICAL", "user": "ADMIN", "ip": "203.0.113.88"},
        {"level": " error ", "user": " Fatima ", "ip": "192.168.1.12"},
        {"level": "INFO", "user": None, "ip": "192.168.1.13"},
    ]
    print(f"\n1. Logs bruts au départ : {len(donnees_brutes)}")
    # Test du filtrage :
    logs_filtres = list(filtrer_les_logs(donnees_brutes))
    print(f"2. Logs après filtrage (filter + lambda) : {len(logs_filtres)} retenus")
    # Test de la normalisation :
    logs_propres = list(normaliser_flux(logs_filtres))
    print("\n3. Logs après normalisation (map + f-strings) :")
    for log in logs_propres:
        print("  ->", log["summary"])
    # Test du routage :
    print("\n4. Test de routage (match-case) :")
    exemples = [
        ("192.168.1.50", 443, "HTTPS"),               # Tuple
        {"level": "ERROR", "payload": {"code": 500}}, # Dict erreur
        {"level": "CRITICAL", "user": "root"},        # Dict critique
        "Ligne brute sans format JSON",               # String brute
    ]
    for ex in exemples:
        print(f"  Entrée: {str(ex):<45} -> {router_le_log(ex)}")

    print("\nFin de la démonstration")