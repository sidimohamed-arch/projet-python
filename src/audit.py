"""Étudiant 3 : rapport d'audit des variables de portée (globals, locals).

Ce module contient :
- VariableAudit : la description d'une variable trouvée dans une portée ;
- audit_scopes : la fonction qui inventorie les variables globales et locales ;
- format_audit_report : la fonction qui met cet inventaire en forme pour l'affichage ;
- export_audit_report : la fonction qui écrit ce rapport dans un fichier.

Le rapport donne le type et la taille des variables, jamais leur valeur : un rapport d'audit
peut être partagé, et il ne doit pas exposer un mot de passe ou une donnée sensible.
"""

# Annotations récentes, non évaluées à l'exécution.
from __future__ import annotations

# inspect : reconnaît modules, classes et fonctions.
import inspect

# getsizeof : taille en mémoire d'un objet.
import sys

# Types utilisés dans les signatures.
from collections.abc import Iterable, Mapping

# dataclass : génère le constructeur.
from dataclasses import dataclass

# Path : chemin de fichier.
from pathlib import Path

# Any : n'importe quel type.
from typing import Any


# frozen=True : entrée immuable.
@dataclass(frozen=True)
# Informations sur une variable.
class VariableAudit:
    """Description d'une variable trouvée dans une portée.

    Attributes:
        scope: Portée de la variable, "global" ou "local".
        name: Nom de la variable.
        type_name: Nom du type de sa valeur.
        size_bytes: Taille de l'objet en octets, sans compter les objets qu'il contient.
        shadows_global: True si cette variable locale masque une globale de même nom.
    """

    # "global" ou "local".
    scope: str
    # Nom de la variable.
    name: str
    # Nom du type, jamais la valeur.
    type_name: str
    # Taille en octets.
    size_bytes: int
    # True si la locale masque une globale.
    shadows_global: bool = False


# Signature : str x Any -> bool
def _is_variable(name: str, value: Any) -> bool:
    """Indique si un nom de portée désigne une variable utile à auditer.

    Args:
        name: Le nom trouvé dans la portée.
        value: La valeur associée à ce nom.

    Returns:
        False pour les noms spéciaux de Python (__name__...), les modules, les classes et
        les fonctions, qui remplissent globals() sans être des données du programme.
    """
    # Noms créés par Python (__name__...).
    if name.startswith("__") and name.endswith("__"):
        # Pas une donnée du programme.
        return False
    # Ni module, ni classe, ni fonction.
    return not (inspect.ismodule(value) or inspect.isclass(value) or inspect.isroutine(value))


# Signature : Mapping[str, Any] x Mapping[str, Any] -> list[VariableAudit]
def audit_scopes(global_vars: Mapping[str, Any], local_vars: Mapping[str, Any]) -> list[VariableAudit]:
    """Inventorie les variables de deux portées.

    Les portées sont passées en argument : appelé ici, globals() renverrait les variables de ce
    module, et non celles du code à auditer. C'est donc à l'appelant de les fournir.

    Args:
        global_vars: Les variables globales de l'appelant, obtenues avec globals().
        local_vars: Les variables locales de l'appelant, obtenues avec locals().

    Returns:
        Les variables globales triées par nom, suivies des variables locales triées par nom.

    Example:
        >>> entrees = audit_scopes(globals(), locals())
    """
    # Une entrée par variable globale.
    entries = [
        # Portée, nom, type et taille, sans la valeur.
        VariableAudit("global", name, type(value).__name__, sys.getsizeof(value))
        # Tri par nom, pour un rapport stable.
        for name, value in sorted(global_vars.items())
        # Garde seulement les données.
        if _is_variable(name, value)
    ]
    # Ajoute les variables locales.
    entries += [
        # Signale une locale qui masque une globale.
        VariableAudit("local", name, type(value).__name__, sys.getsizeof(value), name in global_vars)
        # Même tri par nom.
        for name, value in sorted(local_vars.items())
        # Même filtre.
        if _is_variable(name, value)
    ]
    # Globales d'abord, puis locales.
    return entries


# Signature : Iterable[VariableAudit] -> str
def format_audit_report(entries: Iterable[VariableAudit]) -> str:
    """Met un inventaire de variables en forme, sous la forme d'un tableau de texte.

    Args:
        entries: Les variables à présenter, par exemple le résultat de audit_scopes.

    Returns:
        Le rapport, prêt à être affiché ou écrit dans un fichier.
    """
    # Ligne des titres.
    rows = [("Portée", "Nom", "Type", "Octets", "Remarque")]
    # Chaque entrée devient des cellules de texte.
    rows += [
        # Une ligne du tableau.
        (
            # Colonne "Portée".
            entry.scope,
            # Colonne "Nom".
            entry.name,
            # Colonne "Type".
            entry.type_name,
            # Colonne "Octets", convertie en texte.
            str(entry.size_bytes),
            # Colonne "Remarque", parfois vide.
            "masque une globale" if entry.shadows_global else "",
        )
        # Une ligne par entrée.
        for entry in entries
    ]

    # Largeur de la plus longue cellule par colonne.
    widths = [max(len(cell) for cell in column) for column in zip(*rows, strict=True)]

    # Texte final de chaque ligne.
    lines = [
        # Aligne les cellules, sans espace en fin de ligne.
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        # Pour chaque ligne, titres compris.
        for row in rows
    ]
    # Réunit les lignes en un seul texte.
    return "\n".join(lines)


# Signature : Iterable[VariableAudit] x str | Path -> Path
def export_audit_report(entries: Iterable[VariableAudit], path: str | Path) -> Path:
    """Écrit le rapport d'audit dans un fichier texte, en remplaçant le fichier s'il existe déjà.

    Args:
        entries: Les variables à présenter, par exemple le résultat de audit_scopes.
        path: Le chemin du fichier à écrire. Les dossiers manquants sont créés.

    Returns:
        Le chemin du fichier écrit.

    Raises:
        OSError: Si le fichier ne peut pas être écrit, par exemple faute de droits.

    Example:
        >>> export_audit_report(audit_scopes(globals(), locals()), "reports/audit.txt")
    """
    # Accepte un texte ou un Path.
    report_path = Path(path)
    # Crée les dossiers manquants.
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # UTF-8 : préserve les accents sous Windows.
    report_path.write_text(format_audit_report(entries) + "\n", encoding="utf-8")
    # Renvoie le chemin écrit.
    return report_path
