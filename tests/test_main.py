"""Tests de la ligne de commande."""

# Permet d'écrire les annotations récentes sans les évaluer à l'exécution.
from __future__ import annotations

# Path : décrit les dossiers temporaires fournis par pytest.
from pathlib import Path

# pytest fournit le type CaptureFixture, qui capture ce que le programme affiche.
import pytest

# On importe la fonction à tester, comme si elle était appelée depuis le terminal.
from main import main


# Signature : reçoit le dossier temporaire et le capteur d'affichage de pytest, et ne renvoie rien.
def test_analyze_runs_on_the_provided_sample(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """L'analyse du jeu de test fourni détecte les injections et écrit le rapport d'audit."""
    # Le rapport va dans le dossier temporaire, pour ne rien laisser dans le projet.
    report = tmp_path / "audit.txt"

    # On lance la commande complète, sans détailler les alertes.
    code = main(["analyze", "--input", "data/sample", "--audit-output", str(report), "--show", "0"])

    # On récupère ce que la commande a affiché.
    output = capsys.readouterr().out
    # Le code 0 indique une réussite.
    assert code == 0
    # data/sample/ground_truth.jsonl annonce 34 requêtes d'injection.
    assert "web_injection : 34" in output
    # Le rapport doit contenir les variables locales de la fonction analyze.
    assert "blacklist" in report.read_text(encoding="utf-8")


# Signature : reçoit le dossier temporaire et le capteur d'affichage de pytest, et ne renvoie rien.
def test_show_limits_the_detailed_alerts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """L'option --show limite le détail, sans changer les totaux."""
    # On demande une seule alerte détaillée.
    main(["analyze", "--audit-output", str(tmp_path / "audit.txt"), "--show", "1"])

    # On récupère ce que la commande a affiché.
    output = capsys.readouterr().out
    # Seules les lignes détaillées commencent par un crochet.
    assert sum(line.startswith("[") for line in output.splitlines()) == 1
    # Le total continue de compter toutes les injections.
    assert "web_injection : 34" in output


# Signature : reçoit le dossier temporaire et le capteur d'affichage de pytest, et ne renvoie rien.
def test_missing_input_gives_a_clean_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Un dossier absent donne un message et le code 1, sans trace d'erreur Python."""
    # Ce dossier n'existe pas.
    missing = tmp_path / "absent"

    # On lance l'analyse sur ce dossier.
    code = main(["analyze", "--input", str(missing)])

    # Le code 1 signale l'échec.
    assert code == 1
    # Le message doit désigner le vrai problème : l'absence de logs, pas la blacklist.
    assert "Aucun fichier de logs" in capsys.readouterr().err


# Signature : reçoit le dossier temporaire et le capteur d'affichage de pytest, et ne renvoie rien.
def test_folder_without_logs_gives_a_clean_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Un dossier sans fichier .log donne un message et le code 1."""
    # La blacklist existe, mais aucun fichier de logs.
    (tmp_path / "blacklist.txt").write_text("1.2.3.4\n", encoding="utf-8")

    # On lance l'analyse sur ce dossier.
    code = main(["analyze", "--input", str(tmp_path)])

    # Le code 1 signale l'échec.
    assert code == 1
    # Le message doit indiquer le problème.
    assert "Aucun fichier de logs" in capsys.readouterr().err


# Signature : reçoit le dossier temporaire et le capteur d'affichage de pytest, et ne renvoie rien.
def test_blacklist_and_broken_lines_are_handled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """La blacklist du dossier est utilisée, et une ligne illisible n'arrête pas l'analyse."""
    # La blacklist se trouve à côté des logs.
    (tmp_path / "blacklist.txt").write_text("1.2.3.4\n", encoding="utf-8")
    # Une ligne JSON coupée, une chaîne brute, puis une ligne valide d'une IP blacklistée.
    lines = (
        '{"ip":"coupé\nkernel: eth0 link up\n2026-10-01 | info | 1.2.3.4:22/TCP | u1 | auth | LOGIN | ok\n'
    )
    # On écrit ces lignes dans un fichier de logs.
    (tmp_path / "app.log").write_text(lines, encoding="utf-8")

    # On lance l'analyse sur ce dossier.
    code = main(["analyze", "--input", str(tmp_path), "--audit-output", str(tmp_path / "audit.txt")])

    # L'analyse doit réussir malgré les lignes inutilisables.
    assert code == 0
    # Seule la ligne valide doit produire une alerte.
    assert "blacklisted_ip : 1" in capsys.readouterr().out


# Signature : reçoit le capteur d'affichage de pytest, et ne renvoie rien.
def test_unknown_command_shows_usage(capsys: pytest.CaptureFixture[str]) -> None:
    """Une commande inconnue rappelle l'usage et renvoie le code 2."""
    # On lance le programme avec une commande qui n'existe pas.
    code = main(["inconnue"])

    # Le code 2 signale une erreur d'utilisation.
    assert code == 2
    # Le message doit citer la nouvelle commande.
    assert "analyze" in capsys.readouterr().err
