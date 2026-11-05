"""Tests du rapport d'audit des variables de portée."""

# Permet d'écrire les annotations récentes sans les évaluer à l'exécution.
from __future__ import annotations

# Import utilisé par le test sur le filtrage : un module ne doit pas apparaître dans le rapport.
import math

# Path : décrit le type du dossier temporaire fourni par pytest.
from pathlib import Path

# On importe la classe et les trois fonctions à tester.
from src.audit import VariableAudit, audit_scopes, export_audit_report, format_audit_report


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


# Signature : pytest fournit tmp_path, un dossier temporaire propre à ce test.
def test_export_writes_the_report_in_utf8_and_creates_folders(tmp_path: Path) -> None:
    """Le fichier contient le rapport, avec ses accents, même si son dossier n'existait pas."""
    # Le sous-dossier "rapports" n'existe pas encore : la fonction doit le créer.
    target = tmp_path / "rapports" / "audit.txt"
    # On prépare une petite liste d'entrées, pour la réutiliser dans le résultat attendu.
    entries = audit_scopes({"seuil": 5}, {})

    # On exporte le rapport et on récupère le chemin du fichier écrit.
    written = export_audit_report(entries, target)

    # La fonction doit renvoyer le chemin demandé.
    assert written == target
    # On relit en UTF-8 : le contenu doit être le rapport, suivi d'un retour à la ligne final.
    assert target.read_text(encoding="utf-8") == format_audit_report(entries) + "\n"


# Signature : pytest fournit tmp_path, un dossier temporaire propre à ce test.
def test_export_accepts_a_text_path_and_replaces_the_old_report(tmp_path: Path) -> None:
    """Un chemin en texte est accepté, et un nouvel export remplace l'ancien rapport."""
    # On place un ancien contenu dans le fichier.
    target = tmp_path / "audit.txt"
    # Ce texte doit disparaître après l'export.
    target.write_text("ancien rapport", encoding="utf-8")

    # str() fournit le chemin sous forme de texte ; aucune variable n'est à présenter.
    export_audit_report([], str(target))

    # L'ancien contenu ne doit plus être présent.
    assert "ancien rapport" not in target.read_text(encoding="utf-8")


# Signature : pytest fournit tmp_path, un dossier temporaire propre à ce test.
def test_exported_file_never_contains_the_values(tmp_path: Path) -> None:
    """Le fichier partagé ne révèle pas la valeur d'une variable sensible."""
    # On exporte une variable sensible, dans le fichier audit.txt du dossier temporaire.
    written = export_audit_report(audit_scopes({}, {"password": "motdepasse123"}), tmp_path / "audit.txt")

    # La valeur ne doit pas se retrouver dans le fichier.
    assert "motdepasse123" not in written.read_text(encoding="utf-8")
