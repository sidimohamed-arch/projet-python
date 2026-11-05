"""Fait par Sidi le 05/11/26

Ce module contient :
- Alert : le résultat renvoyé par une règle lorsqu'elle détecte un problème ;
- les règles de sécurité : des fonctions qui examinent un log à la fois ;
- apply_security_rules : la fonction maître qui applique les règles à un flux de logs.

Les fonctions sont des objets de première classe : on peut les passer en argument
à une autre fonction, comme n'importe quelle valeur. C'est ce qui rend le moteur
modulaire : ajouter une règle revient à écrire une fonction, sans modifier le moteur.
"""

# Annotations récentes, non évaluées à l'exécution.
from __future__ import annotations

# logging : journalise les erreurs.
import logging

# re : expressions régulières.
import re

# Types utilisés dans les signatures.
from collections.abc import Callable, Iterable, Iterator

# dataclass : génère le constructeur.
from dataclasses import dataclass

# Any : n'importe quel type.
from typing import Any

# unquote_plus : décode une URL.
from urllib.parse import unquote_plus

# Journal propre à ce module.
logger = logging.getLogger(__name__)

# Un événement est un dictionnaire.
Event = dict[str, Any]

# Motif compilé une seule fois, pour la rapidité.
INJECTION_PATTERN = re.compile(
    # Traversée de chemin : "../" ou "..\".
    r"\.\.[/\\]"
    # Injection SQL : "' OR ..." ou "' AND ...".
    r"|'\s*(?:or|and)\s"
    # Commentaire SQL : "'--".
    r"|'\s*--"
    # Seconde requête : "; DROP ...".
    r"|;\s*(?:drop|delete|insert|update)\s"
    # Fusion avec une autre requête : "UNION SELECT".
    r"|union\s+select",
    # Insensible à la casse.
    re.IGNORECASE,
)

# Taille maximale du texte cité dans une alerte.
MAX_ALERT_TEXT = 100


# frozen=True : alerte immuable.
@dataclass(frozen=True)
# Informations d'une alerte.
class Alert:
    """Alerte levée par une règle de sécurité.

    Attributes:
        rule: Nom de la règle qui a levé l'alerte.
        severity: Gravité de l'alerte, par exemple "HIGH".
        ip: Adresse IP concernée, ou None si le log n'en contient pas.
        message: Description lisible du problème.
    """

    # Nom de la règle.
    rule: str
    # Niveau de gravité de l'alerte.
    severity: str
    # IP concernée, ou None.
    ip: str | None
    # Description du problème.
    message: str


# Une règle renvoie une alerte ou None.
Rule = Callable[..., Alert | None]


# Signature : Event x **Any -> Alert | None
def blacklisted_ip(event: Event, **config: Any) -> Alert | None:
    """Lève une alerte si l'adresse IP du log est dans la blacklist.

    Args:
        event: Le log à examiner.
        **config: Configuration du moteur. Seule la clé "blacklist" est utilisée ici.

    Returns:
        Une alerte si l'IP est blacklistée, sinon None.
    """
    # .get() : None si la clé manque.
    ip = event.get("ip")

    # Blacklist vide par défaut.
    if ip in config.get("blacklist", frozenset()):
        # IP dangereuse : alerte élevée.
        return Alert("blacklisted_ip", "HIGH", ip, f"Activité de l'IP blacklistée {ip}")

    # Rien à signaler.
    return None


# Signature : Event x **Any -> Alert | None
def web_injection(event: Event, **config: Any) -> Alert | None:
    """Lève une alerte si une requête contient une injection SQL ou une traversée de chemin.

    La détection repose sur des motifs connus : elle repère les attaques courantes, mais une
    attaque volontairement déguisée, par exemple encodée deux fois, peut lui échapper.

    Args:
        event: Le log à examiner.
        **config: Configuration du moteur. Cette règle n'en utilise aucune.

    Returns:
        Une alerte si le chemin ou le payload texte est suspect, sinon None.
    """
    # Choisit le texte selon la forme du payload.
    match event.get("payload"):
        # JSON valide avec un chemin.
        case {"path": str(path)}:
            # On garde le chemin.
            target = path
        # Payload resté en texte.
        case str(text):
            # On garde le texte.
            target = text
        # Rien à analyser dans les autres cas.
        case _:
            # Rien à signaler.
            return None

    # Décode l'URL : "..%2f" devient "../".
    decoded = unquote_plus(target)

    # Cherche le motif dans le texte.
    if INJECTION_PATTERN.search(decoded):
        # !r échappe les retours à la ligne.
        message = f"Tentative d'injection : {target[:MAX_ALERT_TEXT]!r}"
        # Injection : alerte élevée.
        return Alert("web_injection", "HIGH", event.get("ip"), message)

    # Rien à signaler.
    return None


# Signature : Event x **Any -> Alert | None
def critical_level(event: Event, **config: Any) -> Alert | None:
    """Lève une alerte si le log a le niveau CRITICAL.

    Args:
        event: Le log à examiner, avec un niveau déjà normalisé par le pipeline.
        **config: Configuration du moteur. Cette règle n'en utilise aucune.

    Returns:
        Une alerte si le niveau est CRITICAL, sinon None.
    """
    # .get() : None si le log n'a pas de niveau.
    if event.get("level") == "CRITICAL":
        # Cite l'événement dans le message.
        message = f"Événement critique : {event.get('event')}"
        # Alerte de gravité critique.
        return Alert("critical_level", "CRITICAL", event.get("ip"), message)

    # Rien à signaler.
    return None


# Signature : *Rule x **Any -> Iterator[Alert]
def apply_security_rules(*args: Rule, **kwargs: Any) -> Iterator[Alert]:
    """Applique des règles de sécurité à un flux de logs.

    Cette fonction vérifie l'appel, puis délègue le traitement à _evaluate. Comme elle ne
    contient pas de yield, ses vérifications s'exécutent dès l'appel. Dans un générateur,
    elles attendraient la lecture de la première alerte.

    Args:
        *args: Les fonctions de sécurité à appliquer, reçues sous forme de tuple.
        **kwargs: Le flux "events" (obligatoire) et les paramètres de configuration
            transmis à chaque règle, reçus sous forme de dictionnaire.

    Returns:
        Un itérateur qui produit les alertes au fur et à mesure.

    Raises:
        ValueError: Si aucune règle n'est fournie.
        TypeError: Si un élément de args n'est pas une fonction, ou si "events" est absent.

    Example:
        >>> alertes = apply_security_rules(blacklisted_ip, events=flux, blacklist=ips)
    """
    # Sans règle, l'appel est invalide.
    if not args:
        # Arrête l'appel avec un message clair.
        raise ValueError("Il faut au moins une règle de sécurité")

    # Vérifie chaque règle dès l'appel.
    for rule in args:
        # callable() : l'objet peut-il être appelé ?
        if not callable(rule):
            # !r affiche l'élément fautif.
            raise TypeError(f"Une règle doit être une fonction : {rule!r}")

    # Le flux de logs est indispensable.
    if "events" not in kwargs:
        # Argument obligatoire manquant.
        raise TypeError("Le paramètre events est obligatoire")

    # Retire events : reste la configuration.
    events = kwargs.pop("events")

    # Générateur : aucun log lu pour l'instant.
    return _evaluate(args, events, kwargs)


# Signature : tuple[Rule, ...] x Iterable[Event] x dict[str, Any] -> Iterator[Alert]
def _evaluate(rules: tuple[Rule, ...], events: Iterable[Event], config: dict[str, Any]) -> Iterator[Alert]:
    """Passe chaque log dans chaque règle, sans stocker le flux en mémoire.

    Le "_" au début du nom indique une fonction interne à ce module.

    Args:
        rules: Les règles à appliquer, dans l'ordre.
        events: Le flux de logs, qui peut être un générateur de plusieurs Go.
        config: La configuration transmise à chaque règle.

    Yields:
        Chaque alerte, dès qu'une règle la lève.
    """
    # Un seul log en mémoire à la fois.
    for event in events:
        # Chaque log passe dans toutes les règles.
        for rule in rules:
            # Une règle peut lever n'importe quelle erreur.
            try:
                # Appelle la règle avec la configuration.
                alert = rule(event, **config)
            except Exception:
                # La panne d'une règle n'arrête pas l'analyse.
                # getattr : un callable n'a pas toujours de __name__.
                logger.exception("Erreur dans la règle %s", getattr(rule, "__name__", repr(rule)))
                # Passe à la règle suivante.
                continue

            # None : rien à signaler.
            if alert is not None:
                # Rend l'alerte sans la stocker.
                yield alert
