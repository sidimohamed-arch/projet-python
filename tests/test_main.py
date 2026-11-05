"""Tests de la ligne de commande."""

# Annotations récentes, non évaluées à l'exécution.
from __future__ import annotations

# Path : type du dossier temporaire.
from pathlib import Path

# pytest : type du capteur d'affichage.
import pytest

# Fonction à tester.
from main import main


# Signature : Path x pytest.CaptureFixture[str] -> None
def test_analyze_runs_on_the_provided_sample(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """L'analyse du jeu de test fourni détecte les injections et écrit le rapport d'audit."""
    # Rapport dans le dossier temporaire.
    report = tmp_path / "audit.txt"

    # Lance la commande, sans détail d'alertes.
    code = main(["analyze", "--input", "data/sample", "--audit-output", str(report), "--show", "0"])

    # Récupère l'affichage.
    output = capsys.readouterr().out
    # Code 0 : réussite.
    assert code == 0
    # ground_truth.jsonl annonce 34 injections.
    assert "web_injection : 34" in output
    # Le rapport cite les variables locales.
    assert "blacklist" in report.read_text(encoding="utf-8")


# Signature : Path x pytest.CaptureFixture[str] -> None
def test_show_limits_the_detailed_alerts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """L'option --show limite le détail, sans changer les totaux."""
    # Une seule alerte détaillée.
    main(["analyze", "--audit-output", str(tmp_path / "audit.txt"), "--show", "1"])

    # Récupère l'affichage.
    output = capsys.readouterr().out
    # Les lignes détaillées commencent par [.
    assert sum(line.startswith("[") for line in output.splitlines()) == 1
    # Le total compte toutes les injections.
    assert "web_injection : 34" in output


# Signature : Path x pytest.CaptureFixture[str] -> None
def test_missing_input_gives_a_clean_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Un dossier absent donne un message et le code 1, sans trace d'erreur Python."""
    # Ce dossier n'existe pas.
    missing = tmp_path / "absent"

    # On lance l'analyse sur ce dossier.
    code = main(["analyze", "--input", str(missing)])

    # Code 1 : échec.
    assert code == 1
    # Le message désigne l'absence de logs.
    assert "Aucun fichier de logs" in capsys.readouterr().err


# Signature : Path x pytest.CaptureFixture[str] -> None
def test_folder_without_logs_gives_a_clean_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Un dossier sans fichier .log donne un message et le code 1."""
    # Une blacklist, mais aucun fichier de logs.
    (tmp_path / "blacklist.txt").write_text("1.2.3.4\n", encoding="utf-8")

    # On lance l'analyse sur ce dossier.
    code = main(["analyze", "--input", str(tmp_path)])

    # Code 1 : échec.
    assert code == 1
    # Le message doit indiquer le problème.
    assert "Aucun fichier de logs" in capsys.readouterr().err


# Signature : Path x pytest.CaptureFixture[str] -> None
def test_blacklist_and_broken_lines_are_handled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """La blacklist du dossier est utilisée, et une ligne illisible n'arrête pas l'analyse."""
    # Blacklist à côté des logs.
    (tmp_path / "blacklist.txt").write_text("1.2.3.4\n", encoding="utf-8")
    # JSON coupé, chaîne brute, puis ligne valide.
    lines = (
        '{"ip":"coupé\nkernel: eth0 link up\n2026-10-01 | info | 1.2.3.4:22/TCP | u1 | auth | LOGIN | ok\n'
    )
    # Écrit le fichier de logs.
    (tmp_path / "app.log").write_text(lines, encoding="utf-8")

    # On lance l'analyse sur ce dossier.
    code = main(["analyze", "--input", str(tmp_path), "--audit-output", str(tmp_path / "audit.txt")])

    # L'analyse réussit malgré tout.
    assert code == 0
    # Seule la ligne valide alerte.
    assert "blacklisted_ip : 1" in capsys.readouterr().out


# Signature : pytest.CaptureFixture[str] -> None
def test_unknown_command_shows_usage(capsys: pytest.CaptureFixture[str]) -> None:
    """Une commande inconnue rappelle l'usage et renvoie le code 2."""
    # Commande inexistante.
    code = main(["inconnue"])

    # Code 2 : erreur d'utilisation.
    assert code == 2
    # Le message cite la commande analyze.
    assert "analyze" in capsys.readouterr().err
