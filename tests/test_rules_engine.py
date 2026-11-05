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

# On importe la classe, le moteur et les règles à tester.
from src.rules_engine import Alert, apply_security_rules, blacklisted_ip, critical_level, web_injection


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_blacklisted_ip_raises_an_alert() -> None:
    """Seule l'IP présente dans la blacklist déclenche une alerte."""
    # Trois cas : une IP blacklistée, une IP normale et un log sans IP.
    events = [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}, {"ip": None}]

    # list() lit tout le générateur d'alertes : c'est acceptable ici, car le test est très petit.
    alerts = list(apply_security_rules(blacklisted_ip, events=events, blacklist=frozenset({"1.2.3.4"})))

    # Une seule alerte est attendue, pour l'IP blacklistée.
    assert [alert.ip for alert in alerts] == ["1.2.3.4"]


# parametrize relance le test ci-dessous avec chaque chemin d'attaque de la liste.
@pytest.mark.parametrize(
    # Nom du paramètre reçu par le test.
    "path",
    # Valeurs de ce paramètre, avec un chemin par cas.
    [
        # Condition SQL toujours vraie.
        "/search?q=' OR '1'='1",
        # La même attaque, en minuscules et avec des + à la place des espaces.
        "/search?q='+or+'1'='1",
        # Commentaire SQL qui neutralise la fin de la requête.
        "/login?user=admin'--",
        # Seconde requête destructrice.
        "/products?id=1; DROP TABLE users",
        # Fusion avec une autre requête, encodée dans l'URL.
        "/products?id=1%20UNION%20SELECT%20password",
        # Traversée de chemin simple.
        "/../../etc/passwd",
        # Traversée de chemin encodée dans l'URL.
        "/static/..%2f..%2fwindows/win.ini",
    ],
)
# Signature : reçoit un chemin de la liste, et ne renvoie rien (None).
def test_web_injection_detects_attacks(path: str) -> None:
    """Chaque forme d'attaque connue déclenche une alerte, avec l'IP de l'attaquant."""
    # On construit un log qui contient le chemin d'attaque.
    alert = web_injection({"ip": "1.2.3.4", "payload": {"path": path}})

    # La règle doit répondre par une alerte qui désigne l'IP.
    assert alert is not None and alert.ip == "1.2.3.4"


# parametrize relance le test ci-dessous avec chaque chemin légitime de la liste.
@pytest.mark.parametrize(
    # Nom du paramètre reçu par le test.
    "path",
    # Valeurs de ce paramètre, avec un chemin par cas.
    [
        # Page d'accueil.
        "/",
        # Fichier statique, qui contient un point.
        "/static/app.js",
        # Une apostrophe dans une recherche n'est pas une attaque.
        "/search?q=o'reilly",
        # Les mots SQL seuls, dans une recherche normale, ne sont pas une attaque.
        "/search?q=select+union+or+drop",
    ],
)
# Signature : reçoit un chemin de la liste, et ne renvoie rien (None).
def test_web_injection_ignores_normal_paths(path: str) -> None:
    """Un chemin légitime ne déclenche pas de fausse alerte."""
    # La règle ne doit rien signaler.
    assert web_injection({"ip": "1.2.3.4", "payload": {"path": path}}) is None


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_web_injection_reads_text_payloads() -> None:
    """Un JSON cassé, gardé en texte par le pipeline, est quand même analysé."""
    # Ce payload est coupé, mais il contient déjà l'attaque.
    alert = web_injection({"ip": "1.2.3.4", "payload": '{"method":"GET","path":"/../../etc/pa'})

    # La règle doit répondre par une alerte.
    assert alert is not None


# parametrize relance le test ci-dessous avec chaque log sans chemin à analyser.
@pytest.mark.parametrize(
    # Nom du paramètre reçu par le test.
    "event",
    # Valeurs de ce paramètre, avec un log par cas.
    [
        # Clé payload absente, comme pour une chaîne brute.
        {},
        # Payload vide.
        {"payload": None},
        # Payload JSON sans chemin.
        {"payload": {"method": "ssh"}},
        # Chemin qui n'est pas du texte.
        {"payload": {"path": 42}},
    ],
)
# Signature : reçoit un log de la liste, et ne renvoie rien (None).
def test_web_injection_ignores_events_without_a_path(event: dict[str, Any]) -> None:
    """Un log sans texte à analyser ne déclenche ni alerte ni erreur."""
    # La règle ne doit rien signaler.
    assert web_injection(event) is None


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_web_injection_message_cannot_forge_log_lines() -> None:
    """Le texte de l'attaquant est échappé et raccourci dans le message de l'alerte."""
    # L'attaquant ajoute un retour à la ligne, puis un texte très long.
    alert = web_injection({"payload": {"path": "/../x\nFAUX LOG" + "a" * 1000}})

    # Une alerte doit être levée pour que le message puisse être contrôlé.
    assert alert is not None
    # Le vrai retour à la ligne ne doit pas apparaître dans le message.
    assert "\n" not in alert.message
    # Le texte recopié doit être limité : le message ne contient pas les 1000 caractères.
    assert len(alert.message) < 200


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_critical_level_only_reacts_to_critical() -> None:
    """Seul le niveau CRITICAL déclenche une alerte, avec le nom de l'événement."""
    # Un log critique suivi de logs d'autres niveaux, dont un sans niveau.
    events = [
        {"level": "CRITICAL", "ip": None, "event": "DATA_LOSS"},
        {"level": "ERROR"},
        {"level": None},
        {},
    ]

    # Le moteur parcourt tous les logs avec cette seule règle.
    alerts = list(apply_security_rules(critical_level, events=events))

    # Une seule alerte est attendue, et elle doit nommer l'événement.
    assert [alert.message for alert in alerts] == ["Événement critique : DATA_LOSS"]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_all_rules_work_together_on_one_event() -> None:
    """Un même log peut déclencher les trois règles, dans l'ordre où elles sont passées."""
    # Ce log est critique, vient d'une IP blacklistée et contient une injection.
    event = {"ip": "1.2.3.4", "level": "CRITICAL", "event": "HTTP_REQUEST", "payload": {"path": "/../etc"}}

    # Les trois règles sont passées au moteur dans *args.
    alerts = apply_security_rules(
        # Première règle à appliquer.
        blacklisted_ip,
        # Deuxième règle à appliquer.
        web_injection,
        # Troisième règle à appliquer.
        critical_level,
        # Le flux de logs, ici réduit à un seul log.
        events=[event],
        # Configuration utilisée par blacklisted_ip.
        blacklist=frozenset({"1.2.3.4"}),
    )

    # Chaque règle doit avoir réagi, dans l'ordre de l'appel.
    assert [alert.rule for alert in alerts] == ["blacklisted_ip", "web_injection", "critical_level"]


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
