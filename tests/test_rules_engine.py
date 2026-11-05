"""Tests du moteur de règles.

Chaque fonction test_... vérifie un seul comportement et se lance avec : python -m pytest
"""

# Annotations récentes, non évaluées à l'exécution.
from __future__ import annotations

# Iterator : type du générateur infini.
from collections.abc import Iterator

# partial : appelable sans __name__.
from functools import partial

# Any : n'importe quel type.
from typing import Any

# pytest : lanceur et outils de test.
import pytest

# Éléments à tester.
from src.rules_engine import Alert, apply_security_rules, blacklisted_ip, critical_level, web_injection


# Signature : () -> None
def test_blacklisted_ip_raises_an_alert() -> None:
    """Seule l'IP présente dans la blacklist déclenche une alerte."""
    # IP blacklistée, IP normale, log sans IP.
    events = [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}, {"ip": None}]

    # list() lit toutes les alertes.
    alerts = list(apply_security_rules(blacklisted_ip, events=events, blacklist=frozenset({"1.2.3.4"})))

    # Une seule alerte attendue.
    assert [alert.ip for alert in alerts] == ["1.2.3.4"]


# Relance le test avec chaque attaque.
@pytest.mark.parametrize(
    # Nom du paramètre.
    "path",
    # Un chemin par cas.
    [
        # Condition SQL toujours vraie.
        "/search?q=' OR '1'='1",
        # La même, en minuscules et avec des +.
        "/search?q='+or+'1'='1",
        # Commentaire SQL.
        "/login?user=admin'--",
        # Seconde requête destructrice.
        "/products?id=1; DROP TABLE users",
        # UNION SELECT encodé dans l'URL.
        "/products?id=1%20UNION%20SELECT%20password",
        # Traversée de chemin simple.
        "/../../etc/passwd",
        # Traversée de chemin encodée dans l'URL.
        "/static/..%2f..%2fwindows/win.ini",
    ],
)
# Signature : str -> None
def test_web_injection_detects_attacks(path: str) -> None:
    """Chaque forme d'attaque connue déclenche une alerte, avec l'IP de l'attaquant."""
    # Log contenant le chemin d'attaque.
    alert = web_injection({"ip": "1.2.3.4", "payload": {"path": path}})

    # Alerte attendue, avec l'IP.
    assert alert is not None and alert.ip == "1.2.3.4"


# Relance le test avec chaque chemin légitime.
@pytest.mark.parametrize(
    # Nom du paramètre.
    "path",
    # Un chemin par cas.
    [
        # Page d'accueil.
        "/",
        # Fichier statique avec un point.
        "/static/app.js",
        # Apostrophe dans une recherche : pas d'attaque.
        "/search?q=o'reilly",
        # Mots SQL seuls : pas d'attaque.
        "/search?q=select+union+or+drop",
    ],
)
# Signature : str -> None
def test_web_injection_ignores_normal_paths(path: str) -> None:
    """Un chemin légitime ne déclenche pas de fausse alerte."""
    # La règle ne doit rien signaler.
    assert web_injection({"ip": "1.2.3.4", "payload": {"path": path}}) is None


# Signature : () -> None
def test_web_injection_reads_text_payloads() -> None:
    """Un JSON cassé, gardé en texte par le pipeline, est quand même analysé."""
    # Payload coupé, mais déjà suspect.
    alert = web_injection({"ip": "1.2.3.4", "payload": '{"method":"GET","path":"/../../etc/pa'})

    # Alerte attendue.
    assert alert is not None


# Relance le test avec chaque log sans chemin.
@pytest.mark.parametrize(
    # Nom du paramètre.
    "event",
    # Un log par cas.
    [
        # Pas de clé payload.
        {},
        # Payload vide.
        {"payload": None},
        # Payload JSON sans chemin.
        {"payload": {"method": "ssh"}},
        # Chemin qui n'est pas du texte.
        {"payload": {"path": 42}},
    ],
)
# Signature : dict[str, Any] -> None
def test_web_injection_ignores_events_without_a_path(event: dict[str, Any]) -> None:
    """Un log sans texte à analyser ne déclenche ni alerte ni erreur."""
    # La règle ne doit rien signaler.
    assert web_injection(event) is None


# Signature : () -> None
def test_web_injection_message_cannot_forge_log_lines() -> None:
    """Le texte de l'attaquant est échappé et raccourci dans le message de l'alerte."""
    # Retour à la ligne, puis texte très long.
    alert = web_injection({"payload": {"path": "/../x\nFAUX LOG" + "a" * 1000}})

    # Une alerte est attendue.
    assert alert is not None
    # Pas de vrai retour à la ligne.
    assert "\n" not in alert.message
    # Texte cité limité.
    assert len(alert.message) < 200


# Signature : () -> None
def test_critical_level_only_reacts_to_critical() -> None:
    """Seul le niveau CRITICAL déclenche une alerte, avec le nom de l'événement."""
    # Log critique, puis d'autres niveaux.
    events = [
        {"level": "CRITICAL", "ip": None, "event": "DATA_LOSS"},
        {"level": "ERROR"},
        {"level": None},
        {},
    ]

    # Analyse avec cette seule règle.
    alerts = list(apply_security_rules(critical_level, events=events))

    # Une alerte, qui nomme l'événement.
    assert [alert.message for alert in alerts] == ["Événement critique : DATA_LOSS"]


# Signature : () -> None
def test_all_rules_work_together_on_one_event() -> None:
    """Un même log peut déclencher les trois règles, dans l'ordre où elles sont passées."""
    # Critique, IP blacklistée et injection.
    event = {"ip": "1.2.3.4", "level": "CRITICAL", "event": "HTTP_REQUEST", "payload": {"path": "/../etc"}}

    # Les trois règles dans *args.
    alerts = apply_security_rules(
        # Première règle à appliquer.
        blacklisted_ip,
        # Deuxième règle à appliquer.
        web_injection,
        # Troisième règle à appliquer.
        critical_level,
        # Flux réduit à un seul log.
        events=[event],
        # Pour blacklisted_ip.
        blacklist=frozenset({"1.2.3.4"}),
    )

    # Chaque règle réagit, dans l'ordre.
    assert [alert.rule for alert in alerts] == ["blacklisted_ip", "web_injection", "critical_level"]


# Signature : () -> None
def test_several_rules_and_dynamic_config_are_supported() -> None:
    """Le moteur accepte plusieurs règles et un paramètre qu'il ne connaît pas à l'avance."""

    # Règle propre à ce test.
    # Signature : dict[str, Any] x **Any -> Alert | None
    def large_response(event: dict[str, Any], **config: Any) -> Alert | None:
        """Lève une alerte si la réponse dépasse la limite configurée."""
        # Compare la taille à la limite.
        if event["bytes"] > config["max_bytes"]:
            # Limite dépassée : alerte.
            return Alert("large_response", "LOW", event["ip"], "Réponse volumineuse")
        # La limite est respectée : rien à signaler.
        return None

    # Un log qui déclenche les deux règles.
    events = [{"ip": "1.2.3.4", "bytes": 900}]

    # max_bytes arrive dans **kwargs.
    alerts = apply_security_rules(
        # Première règle à appliquer.
        blacklisted_ip,
        # Seconde règle à appliquer.
        large_response,
        # Le flux de logs à analyser.
        events=events,
        # Pour blacklisted_ip.
        blacklist=frozenset({"1.2.3.4"}),
        # Pour large_response.
        max_bytes=100,
    )

    # Les deux règles réagissent, dans l'ordre.
    assert [alert.rule for alert in alerts] == ["blacklisted_ip", "large_response"]


# Signature : () -> None
def test_events_are_read_lazily() -> None:
    """Le flux est lu à la demande : un flux infini ne bloque pas le moteur."""

    # Signature : () -> Iterator[dict[str, Any]]
    def endless_events() -> Iterator[dict[str, Any]]:
        """Produit des logs sans jamais s'arrêter."""
        # Boucle infinie.
        while True:
            # Donne un log, puis se met en pause.
            yield {"ip": "1.2.3.4"}

    # Aucun log lu à cet appel.
    alerts = apply_security_rules(blacklisted_ip, events=endless_events(), blacklist=frozenset({"1.2.3.4"}))

    # Bloquerait si le flux était chargé en entier.
    assert next(alerts).ip == "1.2.3.4"


# Signature : () -> None
def test_failing_rule_does_not_stop_the_other_rules() -> None:
    """Une règle qui plante n'empêche pas les autres de s'exécuter."""

    # Signature : dict[str, Any] x **Any -> Alert | None
    def broken_rule(event: dict[str, Any], **config: Any) -> Alert | None:
        """Simule une règle défaillante."""
        # L'erreur est levée à chaque appel.
        raise KeyError("champ absent")

    # La règle en panne passe en premier.
    alerts = apply_security_rules(
        # La règle en panne.
        broken_rule,
        # La règle saine, encore appelée.
        blacklisted_ip,
        # Un log avec une IP blacklistée.
        events=[{"ip": "1.2.3.4"}],
        # Blacklist contenant cette IP.
        blacklist=frozenset({"1.2.3.4"}),
    )

    # Seule la règle saine alerte.
    assert [alert.rule for alert in alerts] == ["blacklisted_ip"]


# Signature : () -> None
def test_failing_rule_without_a_name_does_not_stop_the_analysis() -> None:
    """Une règle sans __name__ (ici un partial) qui plante ne fait pas planter le moteur."""

    # Signature : dict[str, Any] x **Any -> Alert | None
    def broken_rule(event: dict[str, Any], **config: Any) -> Alert | None:
        """Simule une règle défaillante."""
        # L'erreur est levée à chaque appel.
        raise KeyError("champ absent")

    # partial : appelable sans __name__.
    alerts = apply_security_rules(partial(broken_rule), events=[{"ip": "1.2.3.4"}])

    # L'analyse se termine sans alerte.
    assert list(alerts) == []


# Relance le test avec chaque cas.
@pytest.mark.parametrize(
    # Noms des paramètres.
    ("args", "kwargs", "error"),
    # Un tuple par cas.
    [
        # Aucune règle.
        ((), {"events": []}, ValueError),
        # Une règle qui n'est pas une fonction.
        (("pas_une_fonction",), {"events": []}, TypeError),
        # Le flux events est absent.
        ((blacklisted_ip,), {}, TypeError),
    ],
)
# Signature : tuple[Any, ...] x dict[str, Any] x type[Exception] -> None
def test_invalid_calls_are_rejected(
    # Les règles passées au moteur.
    args: tuple[Any, ...],
    # Les paramètres nommés passés au moteur.
    kwargs: dict[str, Any],
    # Le type d'erreur attendu.
    error: type[Exception],
) -> None:
    """Un appel invalide échoue immédiatement, avant de lire le moindre log."""
    # Échoue si l'erreur n'est pas levée.
    with pytest.raises(error):
        # Redistribue le tuple et le dictionnaire.
        apply_security_rules(*args, **kwargs)
