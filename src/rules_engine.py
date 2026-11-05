"""Étudiant 3 : moteur de règles de sécurité.

Ce module contient :
- Alert : le résultat renvoyé par une règle lorsqu'elle détecte un problème ;
- les règles de sécurité : des fonctions qui examinent un log à la fois ;
- apply_security_rules : la fonction maître qui applique les règles à un flux de logs.

Les fonctions sont des objets de première classe : on peut les passer en argument
à une autre fonction, comme n'importe quelle valeur. C'est ce qui rend le moteur
modulaire : ajouter une règle revient à écrire une fonction, sans modifier le moteur.
"""

# Permet d'écrire les annotations récentes (ex : "Alert | None") sans les évaluer à l'exécution.
from __future__ import annotations

# logging : affiche les erreurs avec leur contexte, sans arrêter le programme.
import logging

# Types génériques utilisés dans les signatures des fonctions.
from collections.abc import Callable, Iterable, Iterator

# dataclass : génère automatiquement le constructeur d'une classe de données.
from dataclasses import dataclass

# Any : indique qu'une valeur peut être de n'importe quel type.
from typing import Any

# Journal propre à ce module : __name__ vaut ici "src.rules_engine".
logger = logging.getLogger(__name__)

# Alias de type : un événement est un dictionnaire (voir docs/format_logs.md).
# Les clés sont des chaînes, les valeurs ont des types variés (str, datetime, tuple...).
Event = dict[str, Any]


# frozen=True rend l'alerte immuable : une trace de sécurité ne doit pas changer après sa création.
@dataclass(frozen=True)
# La classe regroupe les informations d'une alerte.
class Alert:
    """Alerte levée par une règle de sécurité.

    Attributes:
        rule: Nom de la règle qui a levé l'alerte.
        severity: Gravité de l'alerte, par exemple "HIGH".
        ip: Adresse IP concernée, ou None si le log n'en contient pas.
        message: Description lisible du problème.
    """

    # Nom de la règle qui a détecté le problème.
    rule: str
    # Niveau de gravité de l'alerte.
    severity: str
    # Adresse IP concernée : None si le log n'en contient pas.
    ip: str | None
    # Texte lisible qui décrit le problème.
    message: str


# Alias de type : une règle est une fonction qui renvoie une alerte ou None.
# Les "..." indiquent que ses paramètres ne sont pas imposés à cet endroit.
# Défini après Alert, car cette ligne est évaluée à l'exécution et a besoin de la classe.
Rule = Callable[..., Alert | None]


# Signature : reçoit un log et la configuration (**config), renvoie une alerte ou None.
def blacklisted_ip(event: Event, **config: Any) -> Alert | None:
    """Lève une alerte si l'adresse IP du log est dans la blacklist.

    Args:
        event: Le log à examiner.
        **config: Configuration du moteur. Seule la clé "blacklist" est utilisée ici.

    Returns:
        Une alerte si l'IP est blacklistée, sinon None.
    """
    # .get() renvoie None si la clé manque, alors que event["ip"] lèverait une KeyError.
    # C'est utile pour les chaînes brutes, qui n'ont pas d'adresse IP.
    ip = event.get("ip")

    # Sans blacklist fournie, on utilise un frozenset vide : aucune IP ne peut alors correspondre.
    # La recherche dans un frozenset est quasi instantanée, quelle que soit sa taille.
    if ip in config.get("blacklist", frozenset()):
        # L'IP est connue comme dangereuse : la règle renvoie une alerte de gravité élevée.
        return Alert("blacklisted_ip", "HIGH", ip, f"Activité de l'IP blacklistée {ip}")

    # None signifie que cette règle n'a rien détecté sur ce log.
    return None


# Signature : *args reçoit les règles dans un tuple, **kwargs reçoit les options nommées dans un
# dictionnaire, et la fonction renvoie un itérateur d'alertes.
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
    # Sans règle, l'analyse ne produirait rien : c'est forcément une erreur d'appel.
    if not args:
        # On arrête l'appel tout de suite avec un message clair.
        raise ValueError("Il faut au moins une règle de sécurité")

    # On vérifie chaque règle maintenant, pour éviter une erreur en plein milieu d'un gros fichier.
    for rule in args:
        # callable() indique si un objet peut être appelé avec des parenthèses.
        if not callable(rule):
            # !r affiche l'objet tel quel dans le message, pour repérer facilement l'élément fautif.
            raise TypeError(f"Une règle doit être une fonction : {rule!r}")

    # Le flux de logs est indispensable : le reste de la configuration dépend des règles.
    if "events" not in kwargs:
        # TypeError est l'erreur habituelle de Python quand un argument obligatoire manque.
        raise TypeError("Le paramètre events est obligatoire")

    # pop() lit "events" et le retire : kwargs ne contient ensuite que la configuration des règles.
    events = kwargs.pop("events")

    # _evaluate est un générateur : cet appel ne lit encore aucun log.
    return _evaluate(args, events, kwargs)


# Signature : reçoit le tuple de règles, le flux de logs et la configuration, renvoie un itérateur d'alertes.
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
    # Un seul log est en mémoire à chaque tour : la RAM ne dépend pas de la taille des fichiers.
    for event in events:
        # Chaque log est soumis à toutes les règles.
        for rule in rules:
            # try surveille l'appel de la règle, car elle peut lever n'importe quelle erreur.
            try:
                # "rule" contient une fonction : on l'appelle comme une fonction normale.
                # **config redistribue le dictionnaire : {"blacklist": ips} devient blacklist=ips.
                alert = rule(event, **config)
            except Exception:
                # Exception volontairement large : une règle peut venir de n'importe quel module,
                # et sa panne ne doit pas interrompre l'analyse de plusieurs Go.
                # logger.exception enregistre aussi le détail de l'erreur pour le débogage.
                # getattr : un callable (ex : functools.partial) n'a pas toujours de __name__, et le
                # traitement de l'erreur ne doit surtout pas lever lui-même une nouvelle erreur.
                logger.exception("Erreur dans la règle %s", getattr(rule, "__name__", repr(rule)))
                # On abandonne cette règle pour ce log et on passe à la suivante.
                continue

            # On garde uniquement les vrais résultats : None signifie "rien à signaler".
            if alert is not None:
                # yield rend l'alerte tout de suite et met la fonction en pause jusqu'à la demande
                # suivante : les alertes ne s'accumulent pas dans une liste en mémoire.
                yield alert
