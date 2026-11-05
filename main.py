"""Point d'entrée du projet (CLI principale, à compléter par l'étudiant 3).

Pour l'instant, seule la génération des logs est disponible :
    python main.py generate --size-mb 10
"""

from __future__ import annotations

import sys

from src import log_generator


def main(argv: list[str]) -> int:
    """Oriente la commande vers le module concerné."""
    match argv:
        case ["generate", *arguments]:
            return log_generator.main(arguments)
        case _:
            print("Usage : python main.py generate [options]", file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
