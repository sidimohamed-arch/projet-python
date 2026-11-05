"""Tests du moteur de règles.

Chaque fonction test_... vérifie un seul comportement et se lance avec : python -m pytest
"""

# Permet d'écrire les annotations récentes sans les évaluer à l'exécution.
from __future__ import annotations

# Iterator décrit le générateur infini du test de lecture en flux.
from collections.abc import Iterator

# partial crée une fonction appelable qui n'a pas de __name__.
from functools import partial

# Any : indique qu'une valeur peut être de n'importe quel type.
from typing import Any

# pytest fournit le lanceur de tests, pytest.raises et les tests paramétrés.
import pytest

# On importe la classe, le moteur et la règle à tester.
from src.rules_engine import Alert, apply_security_rules, blacklisted_ip


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_blacklisted_ip_raises_an_alert() -> None:
    """Seule l'IP présente dans la blacklist déclenche une alerte."""
    # Trois cas : une IP blacklistée, une IP normale et un log sans IP.
    events = [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}, {"ip": None}]

    # list() lit tout le générateur d'alertes : c'est acceptable ici, car le test est très petit.
    alerts = list(apply_security_rules(blacklisted_ip, events=events, blacklist=frozenset({"1.2.3.4"})))

    # Une seule alerte est attendue, pour l'IP blacklistée.
    assert [alert.ip for alert in alerts] == ["1.2.3.4"]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_several_rules_and_dynamic_config_are_supported() -> None:
    """Le moteur accepte plusieurs règles et un paramètre qu'il ne connaît pas à l'avance."""

    # Règle définie uniquement pour ce test : le moteur n'a pas besoin de la connaître à l'avance.
    # Signature : même forme qu'une vraie règle, avec un log et la configuration, puis une alerte ou None.
    def large_response(event: dict[str, Any], **config: Any) -> Alert | None:
        """Lève une alerte si la réponse dépasse la limite configurée."""
        # On compare la taille de la réponse à la limite reçue dans la configuration.
        if event["bytes"] > config["max_bytes"]:
            # La limite est dépassée : la règle renvoie une alerte.
            return Alert("large_response", "LOW", event["ip"], "Réponse volumineuse")
        # La limite est respectée : rien à signaler.
        return None

    # Un seul log, qui doit déclencher les deux règles.
    events = [{"ip": "1.2.3.4", "bytes": 900}]

    # max_bytes arrive dans **kwargs, puis le moteur le transmet à chaque règle.
    alerts = apply_security_rules(
        # Première règle à appliquer.
        blacklisted_ip,
        # Seconde règle à appliquer.
        large_response,
        # Le flux de logs à analyser.
        events=events,
        # Configuration utilisée par blacklisted_ip.
        blacklist=frozenset({"1.2.3.4"}),
        # Configuration utilisée par large_response.
        max_bytes=100,
    )

    # Les deux règles ont réagi au même log, dans l'ordre où elles ont été passées.
    assert [alert.rule for alert in alerts] == ["blacklisted_ip", "large_response"]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_events_are_read_lazily() -> None:
    """Le flux est lu à la demande : un flux infini ne bloque pas le moteur."""

    # Signature : sans argument, renvoie un itérateur de logs.
    def endless_events() -> Iterator[dict[str, Any]]:
        """Produit des logs sans jamais s'arrêter."""
        # La boucle ne se termine jamais : seule une lecture à la demande peut fonctionner.
        while True:
            # yield donne un log, puis met la fonction en pause jusqu'à la demande suivante.
            yield {"ip": "1.2.3.4"}

    # Cet appel ne doit lire aucun log : il prépare seulement le générateur d'alertes.
    alerts = apply_security_rules(blacklisted_ip, events=endless_events(), blacklist=frozenset({"1.2.3.4"}))

    # Si le moteur chargeait tout le flux en mémoire, cette ligne ne se terminerait jamais.
    assert next(alerts).ip == "1.2.3.4"


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_failing_rule_does_not_stop_the_other_rules() -> None:
    """Une règle qui plante n'empêche pas les autres de s'exécuter."""

    # Signature : même forme qu'une vraie règle, même si celle-ci ne renvoie jamais rien.
    def broken_rule(event: dict[str, Any], **config: Any) -> Alert | None:
        """Simule une règle défaillante."""
        # L'erreur est levée à chaque appel.
        raise KeyError("champ absent")

    # broken_rule passe en premier : blacklisted_ip doit quand même s'exécuter ensuite.
    alerts = apply_security_rules(
        # La règle en panne.
        broken_rule,
        # La règle saine, qui doit encore être appelée.
        blacklisted_ip,
        # Un seul log, qui contient une IP blacklistée.
        events=[{"ip": "1.2.3.4"}],
        # La blacklist qui contient cette IP.
        blacklist=frozenset({"1.2.3.4"}),
    )

    # Seule l'alerte de la règle saine doit être produite.
    assert [alert.rule for alert in alerts] == ["blacklisted_ip"]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_failing_rule_without_a_name_does_not_stop_the_analysis() -> None:
    """Une règle sans __name__ (ici un partial) qui plante ne fait pas planter le moteur."""

    # Signature : même forme qu'une vraie règle, même si celle-ci ne renvoie jamais rien.
    def broken_rule(event: dict[str, Any], **config: Any) -> Alert | None:
        """Simule une règle défaillante."""
        # L'erreur est levée à chaque appel.
        raise KeyError("champ absent")

    # Un partial est appelable, mais ne possède pas d'attribut __name__.
    alerts = apply_security_rules(partial(broken_rule), events=[{"ip": "1.2.3.4"}])

    # L'analyse se termine normalement, sans aucune alerte.
    assert list(alerts) == []


# parametrize relance le test ci-dessous avec chacun des trois cas de la liste.
@pytest.mark.parametrize(
    # Noms des paramètres reçus par le test.
    ("args", "kwargs", "error"),
    # Valeurs de ces paramètres, avec un tuple par cas.
    [
        # Aucune règle.
        ((), {"events": []}, ValueError),
        # Une règle qui n'est pas une fonction.
        (("pas_une_fonction",), {"events": []}, TypeError),
        # Le flux events est absent.
        ((blacklisted_ip,), {}, TypeError),
    ],
)
# Signature : reçoit un cas de la liste, et ne renvoie rien (None).
def test_invalid_calls_are_rejected(
    # Les règles passées au moteur.
    args: tuple[Any, ...],
    # Les paramètres nommés passés au moteur.
    kwargs: dict[str, Any],
    # Le type d'erreur attendu.
    error: type[Exception],
) -> None:
    """Un appel invalide échoue immédiatement, avant de lire le moindre log."""
    # pytest.raises fait échouer le test si l'erreur attendue n'est pas levée.
    with pytest.raises(error):
        # * et ** redistribuent le tuple et le dictionnaire en arguments de l'appel.
        apply_security_rules(*args, **kwargs)
