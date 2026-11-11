"""Étudiant 3 : rapport d'audit des variables de portée (globals, locals).

Ce module contient :
- VariableAudit : la description d'une variable trouvée dans une portée ;
- audit_scopes : la fonction qui inventorie les variables globales et locales ;
- format_audit_report : la fonction qui met cet inventaire en forme pour l'affichage ;
- export_audit_report : la fonction qui écrit ce rapport dans un fichier.

Le rapport donne le type et la taille des variables, jamais leur valeur : un rapport d'audit
peut être partagé, et il ne doit pas exposer un mot de passe ou une donnée sensible.
"""

# Permet d'écrire les annotations récentes (ex : "list[str]") sans les évaluer à l'exécution.
from __future__ import annotations

# inspect : permet de reconnaître les modules, les classes et les fonctions.
import inspect

# sys.getsizeof : donne la taille en mémoire d'un objet.
import sys

# Iterable : tout ce qu'on peut parcourir avec for. Mapping : tout ce qui se lit comme un dictionnaire.
from collections.abc import Iterable, Mapping

# dataclass : génère automatiquement le constructeur d'une classe de données.
from dataclasses import dataclass

# Path : représente un chemin de fichier, quel que soit le système d'exploitation.
from pathlib import Path

# Any : indique qu'une valeur peut être de n'importe quel type.
from typing import Any


# frozen=True rend l'entrée immuable : un constat d'audit ne doit pas changer après sa création.
@dataclass(frozen=True)
# La classe regroupe les informations relevées sur une seule variable.
class VariableAudit:
    """Description d'une variable trouvée dans une portée.

    Attributes:
        scope: Portée de la variable, "global" ou "local".
        name: Nom de la variable.
        type_name: Nom du type de sa valeur.
        size_bytes: Taille de l'objet en octets, sans compter les objets qu'il contient.
        shadows_global: True si cette variable locale masque une globale de même nom.
    """

    # Portée de la variable : "global" ou "local".
    scope: str
    # Nom de la variable dans le code audité.
    name: str
    # Nom du type de la valeur : on ne garde jamais la valeur elle-même.
    type_name: str
    # Taille de l'objet en octets.
    size_bytes: int
    # Valeur par défaut False : une globale ne peut pas masquer une globale.
    shadows_global: bool = False


# Signature : reçoit un nom (str) et une valeur de tout type (Any), renvoie un booléen.
def _is_variable(name: str, value: Any) -> bool:
    """Indique si un nom de portée désigne une variable utile à auditer.

    Args:
        name: Le nom trouvé dans la portée.
        value: La valeur associée à ce nom.

    Returns:
        False pour les noms spéciaux de Python (__name__...), les modules, les classes et
        les fonctions, qui remplissent globals() sans être des données du programme.
    """
    # Les noms entourés de "__" (__name__, __file__...) sont créés par Python, pas par le programme.
    if name.startswith("__") and name.endswith("__"):
        # Ce nom spécial n'est pas une donnée du programme : on l'écarte.
        return False
    # On garde la valeur seulement si ce n'est ni un module, ni une classe, ni une fonction.
    return not (inspect.ismodule(value) or inspect.isclass(value) or inspect.isroutine(value))


# Signature : reçoit deux portées qui se lisent comme des dictionnaires, renvoie une liste d'entrées.
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
    # Cette liste en compréhension crée une entrée par variable globale.
    entries = [
        # Chaque entrée garde la portée, le nom, le nom du type et la taille, mais pas la valeur.
        VariableAudit("global", name, type(value).__name__, sys.getsizeof(value))
        # sorted() trie les paires (nom, valeur) par nom : le rapport reste stable d'une exécution à l'autre.
        for name, value in sorted(global_vars.items())
        # Le filtre retire ce qui n'est pas une donnée du programme.
        if _is_variable(name, value)
    ]
    # += ajoute les variables locales à la suite des variables globales.
    entries += [
        # On teste global_vars au complet : une locale peut aussi masquer une fonction globale.
        VariableAudit("local", name, type(value).__name__, sys.getsizeof(value), name in global_vars)
        # Même tri par nom que pour les globales.
        for name, value in sorted(local_vars.items())
        # Même filtre que pour les globales.
        if _is_variable(name, value)
    ]
    # On renvoie l'inventaire complet : les globales d'abord, puis les locales.
    return entries


# Signature : reçoit n'importe quelle suite d'entrées (liste, générateur...), renvoie le texte du rapport.
def format_audit_report(entries: Iterable[VariableAudit]) -> str:
    """Met un inventaire de variables en forme, sous la forme d'un tableau de texte.

    Args:
        entries: Les variables à présenter, par exemple le résultat de audit_scopes.

    Returns:
        Le rapport, prêt à être affiché ou écrit dans un fichier.
    """
    # La première ligne du tableau contient les titres des colonnes.
    rows = [("Portée", "Nom", "Type", "Octets", "Remarque")]
    # On transforme chaque entrée en cellules de texte, pour pouvoir mesurer leur largeur.
    rows += [
        # Ce tuple représente une ligne du tableau, avec une cellule par colonne.
        (
            # Colonne "Portée".
            entry.scope,
            # Colonne "Nom".
            entry.name,
            # Colonne "Type".
            entry.type_name,
            # Colonne "Octets" : str() convertit le nombre, car les cellules doivent être du texte.
            str(entry.size_bytes),
            # Colonne "Remarque" : elle reste vide si la variable ne masque aucune globale.
            "masque une globale" if entry.shadows_global else "",
        )
        # On crée une ligne pour chaque entrée reçue.
        for entry in entries
    ]

    # zip(*rows) lit le tableau par colonnes : chaque colonne prend la largeur de sa plus longue cellule.
    widths = [max(len(cell) for cell in column) for column in zip(*rows, strict=True)]

    # Cette liste contient le texte final de chaque ligne du tableau.
    lines = [
        # ljust complète chaque cellule avec des espaces ; rstrip retire ceux laissés en fin de ligne.
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        # On répète ce traitement pour chaque ligne, titres compris.
        for row in rows
    ]
    # On réunit les lignes en un seul texte, séparées par un retour à la ligne.
    return "\n".join(lines)


# Signature : reçoit une suite d'entrées et un chemin (texte ou Path), renvoie le chemin du fichier écrit.
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
    # Path() accepte aussi un Path : la suite de la fonction n'a qu'un seul type à gérer.
    report_path = Path(path)
    # parents=True crée toute la chaîne de dossiers ; exist_ok=True accepte un dossier déjà présent.
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # UTF-8 est imposé : sous Windows, l'encodage par défaut pourrait abîmer les accents du rapport.
    report_path.write_text(format_audit_report(entries) + "\n", encoding="utf-8")
    # On renvoie le chemin pour que l'appelant puisse l'afficher à l'utilisateur.
    return report_path
