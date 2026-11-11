"""
Module 1 : Ingestion de Données & Générateurs Mémoire
Fichier : src/ingestion.py
Auteur : Hafsa
Description : Ingestion en streaming (yield et yield from) de fichiers de logs
              sans saturer la mémoire RAM.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any


def parser_ligne_log(line: str) -> dict[str, Any] | None:
    """
    Parse une ligne de log brute (standard ou JSON) en un Dictionnaire structuré.
    Compatible avec le pipeline de Fatima et le main de Sidi Mohamed.
    """
    text = line.strip()
    if not text:
        return None

    # Cas 1 : Ligne au format JSON
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except (ValueError, json.JSONDecodeError):
            return None

        ip = str(data.get("ip", "0.0.0.0"))
        # Création du Tuple immuable exigé par le sujet (IP, Port, Protocole)
        metadata = (ip, int(data.get("port", 0)), str(data.get("proto", "TCP")).upper())

        return {
            "timestamp": str(data.get("timestamp", "")),
            "level": str(data.get("level", "INFO")).upper(),
            "ip": ip,
            "metadata": metadata,  # Tuple (IP, Port, Proto)
            "user": str(data.get("user", data.get("user_id", "anonyme"))).strip(),
            "event": str(data.get("event", "unknown")),
            "payload": data.get("payload", "")
        }

    # Cas 2 : Ligne standard découpée par " | "
    # Format : timestamp | level | ip:port:proto | user | session | event | payload
    fields = [field.strip() for field in text.split(" | ", 6)]
    
    if len(fields) < 4:
        return None

    timestamp = fields[0]
    level = fields[1].upper()
    adresse = fields[2]
    user = fields[3]
    event = fields[5] if len(fields) > 5 else "log"
    raw_payload = fields[6] if len(fields) > 6 else ""

    # Découpage de l'adresse réseau en Tuple immuable
    try:
        parties_reseau = adresse.split(":")
        ip = parties_reseau[0]
        port = int(parties_reseau[1]) if len(parties_reseau) > 1 else 80
        proto = parties_reseau[2].upper() if len(parties_reseau) > 2 else "TCP"
        metadata = (ip, port, proto)
    except (ValueError, IndexError):
        ip = adresse.split(":")[0] if ":" in adresse else adresse
        metadata = (ip, 0, "UNKNOWN")

    # Décodage du payload (soit un dictionnaire JSON, soit une chaîne)
    try:
        payload = json.loads(raw_payload)
    except (ValueError, json.JSONDecodeError):
        payload = raw_payload

    return {
        "timestamp": timestamp,
        "level": level,
        "ip": ip,
        "metadata": metadata,  # Tuple immuable (IP, Port, Protocole)
        "user": user,
        "event": event,
        "payload": payload
    }


def generer_logs_fichier(path: Path | str) -> Iterator[dict[str, Any]]:
    """
    Générateur basé sur 'yield' : lit un fichier ligne par ligne sans charger
    tout le contenu en mémoire vive.
    """
    fichier = Path(path)
    if not fichier.exists():
        return

    # errors="replace" pour éviter de planter sur des caractères non-UTF8
    with fichier.open(encoding="utf-8", errors="replace") as file:
        for line in file:
            event = parser_ligne_log(line)
            if event is not None:
                # yield transmet un log à la fois à la demande
                yield event


def ingestion_multi_sources(*sources: Path | str | Iterable[Path | str]) -> Iterator[dict[str, Any]]:
    """
    Sous-générateur multi-sources utilisant impérativement 'yield from'.
    Accepte soit plusieurs chemins : ingestion_multi_sources(f1, f2)
    soit une liste de chemins    : ingestion_multi_sources([f1, f2])
    """
    # Si l'utilisateur passe une liste directe comme premier argument
    fichiers: list[Path | str] = []
    for s in sources:
        if isinstance(s, (list, tuple, set, Iterable)) and not isinstance(s, (str, Path)):
            fichiers.extend(s)
        else:
            fichiers.append(s)

    for fichier in fichiers:
        # yield from délègue la génération au premier générateur
        yield from generer_logs_fichier(fichier)


# ---------------------------------------------------------------------
# TEST D'INTÉGRATION AVEC LE PIPELINE DE FATIMA
# ---------------------------------------------------------------------
if __name__ == "__main__":
    print("=== TEST DU MODULE 1 (HAFSA) AVEC LE PIPELINE DE FATIMA ===")

    # Simulation d'un fichier de test
    fichier_test = Path("test_sample.log")
    lignes_exemples = [
        "2026-11-09 14:00:01 | INFO | 192.168.1.10:443:TCP | alice | s1 | login | Connexion réussie\n",
        "2026-11-09 14:00:05 | ERROR | 10.0.0.5:22:SSH | root | s2 | auth | {\"attempt\": 3, \"code\": 500}\n",
        '{"timestamp": "2026-11-09 14:00:10", "level": "CRITICAL", "ip": "172.16.0.4", "port": 80, "proto": "HTTP", "user": "admin", "event": "breach", "payload": "Attaque"}\n',
        "Ligne corrompue qui doit être ignorée\n"
    ]

    fichier_test.write_text("".join(lignes_exemples), encoding="utf-8")

    try:
        # 1. Ton générateur produit le flux
        flux = ingestion_multi_sources(fichier_test)

        # 2. On affiche les logs produits
        for i, log in enumerate(flux, 1):
            print(f"\nLog #{i} produit par ingestion.py :")
            print(f"  • User     : {log['user']}")
            print(f"  • Level    : {log['level']}")
            print(f"  • IP       : {log['ip']}")
            print(f"  • Metadata : {log['metadata']} (Type: {type(log['metadata']).__name__})")
            print(f"  • Payload  : {log['payload']}")

    finally:
        if fichier_test.exists():
            fichier_test.unlink()
