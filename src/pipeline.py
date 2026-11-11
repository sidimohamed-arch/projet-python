"""Pipeline de transformation et de filtrage des logs réseau."""

def filtrer_les_logs(flux_de_logs):
    """Élimine les entrées vides et les logs mal formés."""
    flux_sans_vide = filter(None, flux_de_logs)
    niveaux_valides = {"INFO", "WARNING", "ERROR", "CRITICAL"}
    
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
    pseudo_propre = str(log.get("user", "")).strip().lower()
    niveau_propre = str(log.get("level", "")).strip().upper()
    adresse_ip = log.get("ip", "0.0.0.0")
    resume = f"[{niveau_propre}] Connexion depuis {adresse_ip} par '{pseudo_propre}'"
    
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
        case str(texte):
            return f"ROUTAGE -> TEXTE BRUT : {texte}"
        case {"level": "ERROR", "payload": {"code": code_erreur}}:
            return f"Erreur avec le code {code_erreur}"
        case {"level": "CRITICAL", "user": pseudo}:
            return f"ROUTAGE -> ALERTE CRITIQUE SUR : {pseudo}"
        case (str(ip), int(port), str(proto)):
            return f"ROUTAGE -> TUPLE RESEAU : {ip}:{port}/{proto}"
        case _:
            return "ROUTAGE -> FORMAT INCONNU"
