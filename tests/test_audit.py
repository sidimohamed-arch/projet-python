"""Tests du rapport d'audit des variables de portée."""

# Annotations récentes, non évaluées à l'exécution.
from __future__ import annotations

# math : module utilisé par le test de filtrage.
import math

# Path : type du dossier temporaire.
from pathlib import Path

# Éléments à tester.
from src.audit import VariableAudit, audit_scopes, export_audit_report, format_audit_report


# Signature : () -> None
def test_variables_are_listed_by_scope_with_their_type() -> None:
    """Les globales passent avant les locales, et chaque portée est triée par nom."""
    # Deux globales dans le désordre, une locale.
    entries = audit_scopes({"seuil": 5, "chemin": "logs"}, {"total": 1.5})

    # Compare portée, nom et type.
    assert [(entry.scope, entry.name, entry.type_name) for entry in entries] == [
        # "chemin" avant "seuil" : tri par nom.
        ("global", "chemin", "str"),
        # La seconde globale.
        ("global", "seuil", "int"),
        # La locale après les globales.
        ("local", "total", "float"),
    ]


# Signature : () -> None
def test_special_names_modules_classes_and_functions_are_ignored() -> None:
    """Seules les données du programme sont auditées."""
    # Des globales de chaque sorte.
    entries = audit_scopes(
        # Nom spécial, module, classe, fonction, variable.
        {"__name__": "x", "math": math, "Classe": VariableAudit, "fn": len, "seuil": 5},
        # Aucune variable locale.
        {},
    )

    # Seule la vraie variable doit rester.
    assert [entry.name for entry in entries] == ["seuil"]


# Signature : () -> None
def test_local_variable_hiding_a_global_is_flagged() -> None:
    """Une locale qui porte le nom d'une globale est signalée, même si cette globale est une fonction."""
    # "seuil" et "max" masquent ; "autre" non.
    entries = audit_scopes({"seuil": 5, "max": max}, {"seuil": 9, "max": 3, "autre": 0})

    # Noms des variables signalées.
    flagged = [entry.name for entry in entries if entry.shadows_global]

    # sorted() : ordre indifférent.
    assert sorted(flagged) == ["max", "seuil"]


# Signature : () -> None
def test_works_with_real_globals_and_locals() -> None:
    """La fonction accepte directement le résultat de globals() et de locals()."""
    # Variable que l'audit doit retrouver.
    secret_local = 42

    # Passe les vraies portées du test.
    entries = audit_scopes(globals(), locals())

    # Trouvée avec la portée "local".
    assert ("local", "secret_local") in [(entry.scope, entry.name) for entry in entries]
    # Utilise la variable dans le test.
    assert secret_local == 42


# Signature : () -> None
def test_report_never_contains_the_values() -> None:
    """Le rapport présente la variable sans révéler sa valeur."""
    # On simule une variable sensible.
    report = format_audit_report(audit_scopes({}, {"password": "motdepasse123"}))

    # Nom visible.
    assert "password" in report
    # Valeur jamais affichée.
    assert "motdepasse123" not in report


# Signature : () -> None
def test_report_columns_are_aligned_and_shadowing_is_visible() -> None:
    """Toutes les colonnes commencent au même endroit et la remarque apparaît."""
    # Entrée construite à la main.
    report = format_audit_report([VariableAudit("local", "seuil", "int", 28, shadows_global=True)])

    # En-tête, puis variable.
    header, row = report.splitlines()

    # Nom aligné sous son titre.
    assert header.index("Nom") == row.index("seuil")
    # Remarque écrite en clair.
    assert "masque une globale" in row


# Signature : () -> None
def test_empty_audit_gives_only_the_header() -> None:
    """Sans variable, le rapport reste valide et ne contient que l'en-tête."""
    # Seuls les cinq titres restent.
    assert format_audit_report([]).split() == ["Portée", "Nom", "Type", "Octets", "Remarque"]


# Signature : Path -> None
def test_export_writes_the_report_in_utf8_and_creates_folders(tmp_path: Path) -> None:
    """Le fichier contient le rapport, avec ses accents, même si son dossier n'existait pas."""
    # Dossier encore inexistant.
    target = tmp_path / "rapports" / "audit.txt"
    # Entrées à exporter.
    entries = audit_scopes({"seuil": 5}, {})

    # Exporte et récupère le chemin.
    written = export_audit_report(entries, target)

    # Renvoie le chemin demandé.
    assert written == target
    # Rapport suivi d'un retour à la ligne.
    assert target.read_text(encoding="utf-8") == format_audit_report(entries) + "\n"


# Signature : Path -> None
def test_export_accepts_a_text_path_and_replaces_the_old_report(tmp_path: Path) -> None:
    """Un chemin en texte est accepté, et un nouvel export remplace l'ancien rapport."""
    # Ancien contenu à remplacer.
    target = tmp_path / "audit.txt"
    # Ce texte doit disparaître.
    target.write_text("ancien rapport", encoding="utf-8")

    # Chemin en texte, sans variable.
    export_audit_report([], str(target))

    # L'ancien contenu a disparu.
    assert "ancien rapport" not in target.read_text(encoding="utf-8")


# Signature : Path -> None
def test_exported_file_never_contains_the_values(tmp_path: Path) -> None:
    """Le fichier partagé ne révèle pas la valeur d'une variable sensible."""
    # Exporte une variable sensible.
    written = export_audit_report(audit_scopes({}, {"password": "motdepasse123"}), tmp_path / "audit.txt")

    # Valeur absente du fichier.
    assert "motdepasse123" not in written.read_text(encoding="utf-8")
