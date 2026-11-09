"""
Module 3 : Agrégation & Sécurité - Détecteur de Force Brute
Fichier : src/detector.py
Auteur : Hafsa
Description : Algorithme de détection d'attaques par force brute combinant
              boucles while, for, break, continue et clause else.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any


def est_un_echec_de_connexion(log: dict[str, Any]) -> bool:
    """Vérifie si un événement correspond à une tentative de connexion échouée."""
    level = str(log.get("level", "")).upper()
    event = str(log.get("event", "")).lower()
    payload = str(log.get("payload", "")).lower()

    # Détection des erreurs, statuts critiques ou mots-clés d'échec
    if level in ("ERROR", "CRITICAL"):
        return True
    if any(mot in payload for mot in ("failed", "failure", "invalide", "echec", "bad_password", "code: 500")):
        return True
    if "auth" in event and level != "INFO":
        return True

    return False


def detecter_force_brute(
    flux_de_logs: Iterable[dict[str, Any]], 
    seuil_echecs: int = 3
) -> list[dict[str, Any]]:
    """
    Détecte les attaques par force brute (X échecs consécutifs).
    
    Exigences du sujet respectées :
    - Boucle 'for' et boucle 'while' combinées.
    - Instructions 'break' et 'continue'.
    - Clause 'else' sur la boucle pour valider le cycle complet.
    """
    # 1. Regroupement des logs par adresse IP
    logs_par_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for log in flux_de_logs:
        # 'continue' : on ignore les entrées invalides
        if not isinstance(log, dict):
            continue

        ip = log.get("ip")
        if not ip:
            continue

        logs_par_ip[ip].append(log)

    alertes_detectees: list[dict[str, Any]] = []

    # 2. Boucle FOR : analyse de l'historique de chaque IP
    for ip, historique in logs_par_ip.items():
        # 'continue' : si l'historique est trop court pour atteindre le seuil
        if len(historique) < seuil_echecs:
            continue

        index = 0
        # 3. Boucle WHILE : fenêtre glissante sur les tentatives
        while index <= len(historique) - seuil_echecs:
            fenetre = historique[index : index + seuil_echecs]

            # 4. Boucle FOR interne : vérification des échecs consécutifs
            for tentative in fenetre:
                if not est_un_echec_de_connexion(tentative):
                    # 'break' : un succès brise la série d'échecs consécutifs
                    break
            else:
                # 5. CLAUSE ELSE DE LA BOUCLE FOR :
                # Exécutée UNIQUEMENT si la boucle s'est terminée SANS 'break'.
                # Prouve que TOUTES les tentatives de la fenêtre sont des échecs !
                derniere_tentative = fenetre[-1]
                premiere_tentative = fenetre[0]

                alertes_detectees.append({
                    "type": "BRUTE_FORCE_ATTACK",
                    "ip": ip,
                    "user": premiere_tentative.get("user", "inconnu"),
                    "echecs_consecutifs": seuil_echecs,
                    "debut": premiere_tentative.get("timestamp"),
                    "fin": derniere_tentative.get("timestamp"),
                    "message": f"Attaque détectée depuis {ip} : {seuil_echecs} échecs consécutifs !"
                })

                # On avance l'index pour éviter de recompter la même attaque
                index += seuil_echecs
                continue

            # Si le 'break' a été déclenché, on avance d'une position
            index += 1

    return alertes_detectees


# ---------------------------------------------------------------------
# TEST DU DETECTEUR (python src/detector.py)
# ---------------------------------------------------------------------
if __name__ == "__main__":
    print("=== TEST DU MODULE 3 : DETECTEUR DE FORCE BRUTE ===")

    # Simulation d'une attaque depuis l'IP 10.0.0.99 (3 échecs consécutifs)
    # et d'une connexion normale depuis 192.168.1.50 (avec un succès qui brise la série)
    donnees_test = [
        {"timestamp": "14:00:01", "ip": "10.0.0.99", "user": "admin", "level": "ERROR", "payload": "failed"},
        {"timestamp": "14:00:02", "ip": "10.0.0.99", "user": "admin", "level": "ERROR", "payload": "failed"},
        {"timestamp": "14:00:03", "ip": "10.0.0.99", "user": "admin", "level": "ERROR", "payload": "failed"},
        
        {"timestamp": "14:00:04", "ip": "192.168.1.50", "user": "alice", "level": "ERROR", "payload": "failed"},
        {"timestamp": "14:00:05", "ip": "192.168.1.50", "user": "alice", "level": "INFO",  "payload": "success"},
        {"timestamp": "14:00:06", "ip": "192.168.1.50", "user": "alice", "level": "ERROR", "payload": "failed"},
    ]

    resultats = detecter_force_brute(donnees_test, seuil_echecs=3)

    print(f"\nNombre d'attaques détectées : {len(resultats)}")
    for alerte in resultats:
        print(f" [ALERTE] {alerte['message']}")
        print(f"          Cible : {alerte['user']} | Période : {alerte['debut']} -> {alerte['fin']}")
