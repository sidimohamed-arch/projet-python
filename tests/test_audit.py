"""Tests du rapport d'audit des variables de portée."""

# Permet d'écrire les annotations récentes sans les évaluer à l'exécution.
from __future__ import annotations

# Import utilisé par le test sur le filtrage : un module ne doit pas apparaître dans le rapport.
import math

# On importe la classe et les deux fonctions à tester.
from src.audit import VariableAudit, audit_scopes, format_audit_report


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_variables_are_listed_by_scope_with_their_type() -> None:
    """Les globales passent avant les locales, et chaque portée est triée par nom."""
    # Deux globales volontairement dans le désordre, et une locale.
    entries = audit_scopes({"seuil": 5, "chemin": "logs"}, {"total": 1.5})

    # On compare la portée, le nom et le type de chaque entrée au résultat attendu.
    assert [(entry.scope, entry.name, entry.type_name) for entry in entries] == [
        # "chemin" passe avant "seuil", car les noms sont triés.
        ("global", "chemin", "str"),
        # La seconde globale, avec son type.
        ("global", "seuil", "int"),
        # La locale arrive après toutes les globales.
        ("local", "total", "float"),
    ]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_special_names_modules_classes_and_functions_are_ignored() -> None:
    """Seules les données du programme sont auditées."""
    # On audite des globales de chaque sorte.
    entries = audit_scopes(
        # Un nom spécial, un module, une classe, une fonction, puis une seule vraie variable.
        {"__name__": "x", "math": math, "Classe": VariableAudit, "fn": len, "seuil": 5},
        # Ce dictionnaire vide indique qu'il n'y a aucune variable locale.
        {},
    )

    # Seule la vraie variable doit rester.
    assert [entry.name for entry in entries] == ["seuil"]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_local_variable_hiding_a_global_is_flagged() -> None:
    """Une locale qui porte le nom d'une globale est signalée, même si cette globale est une fonction."""
    # "seuil" masque une variable, "max" masque une fonction, et "autre" ne masque rien.
    entries = audit_scopes({"seuil": 5, "max": max}, {"seuil": 9, "max": 3, "autre": 0})

    # On garde uniquement les noms des variables signalées.
    flagged = [entry.name for entry in entries if entry.shadows_global]

    # sorted() rend la comparaison indépendante de l'ordre de la liste.
    assert sorted(flagged) == ["max", "seuil"]


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_works_with_real_globals_and_locals() -> None:
    """La fonction accepte directement le résultat de globals() et de locals()."""
    # Cette variable locale doit être retrouvée par l'audit.
    secret_local = 42

    # On passe les vraies portées de ce test, comme le fera le code de production.
    entries = audit_scopes(globals(), locals())

    # La variable doit apparaître dans l'inventaire avec la portée "local".
    assert ("local", "secret_local") in [(entry.scope, entry.name) for entry in entries]
    # Lire la variable ici évite qu'un outil la signale comme inutilisée.
    assert secret_local == 42


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_report_never_contains_the_values() -> None:
    """Le rapport présente la variable sans révéler sa valeur."""
    # On simule une variable sensible.
    report = format_audit_report(audit_scopes({}, {"password": "motdepasse123"}))

    # Le nom de la variable reste visible dans le rapport.
    assert "password" in report
    # Sa valeur ne doit jamais y apparaître.
    assert "motdepasse123" not in report


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_report_columns_are_aligned_and_shadowing_is_visible() -> None:
    """Toutes les colonnes commencent au même endroit et la remarque apparaît."""
    # On construit directement une entrée, pour contrôler exactement ce que reçoit le rapport.
    report = format_audit_report([VariableAudit("local", "seuil", "int", 28, shadows_global=True)])

    # Le rapport doit contenir deux lignes : l'en-tête, puis la variable.
    header, row = report.splitlines()

    # Le nom de la variable doit commencer sous le titre de sa colonne.
    assert header.index("Nom") == row.index("seuil")
    # La remarque doit être écrite en clair dans la ligne.
    assert "masque une globale" in row


# Signature : pytest appelle ce test sans argument, et il ne renvoie rien (None).
def test_empty_audit_gives_only_the_header() -> None:
    """Sans variable, le rapport reste valide et ne contient que l'en-tête."""
    # split() découpe le texte en mots : on doit retrouver uniquement les cinq titres.
    assert format_audit_report([]).split() == ["Portée", "Nom", "Type", "Octets", "Remarque"]
