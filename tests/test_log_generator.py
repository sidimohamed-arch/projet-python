"""Tests du générateur de logs."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from src.log_generator import MIB, GeneratorConfig, main, write_logs

IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _generate(output_dir: Path, seed: int = 42) -> list[bytes]:
    config = GeneratorConfig(
        output_dir=output_dir,
        total_bytes=2 * MIB,
        file_bytes=MIB,
        seed=seed,
        attacks_per_10k=15,
    )
    write_logs(config)
    return [line for path in sorted(output_dir.glob("app-*.log")) for line in path.read_bytes().split(b"\n")]


def _truth(output_dir: Path) -> list[dict]:
    lines = (output_dir / "ground_truth.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_same_seed_gives_identical_output(tmp_path: Path) -> None:
    assert _generate(tmp_path / "a") == _generate(tmp_path / "b")


def test_different_seed_gives_different_output(tmp_path: Path) -> None:
    assert _generate(tmp_path / "a", seed=1) != _generate(tmp_path / "b", seed=2)


def test_size_and_rotation(tmp_path: Path) -> None:
    _generate(tmp_path)
    paths = sorted(tmp_path.glob("app-*.log"))
    assert [path.name for path in paths] == ["app-0001.log", "app-0002.log"]
    total = sum(path.stat().st_size for path in paths)
    assert 2 * MIB <= total < 2 * MIB + 10_000


def test_all_formats_and_dirt_are_present(tmp_path: Path) -> None:
    lines = _generate(tmp_path)
    assert any(line.count(b" | ") == 6 for line in lines)
    assert any(line.startswith(b'{"timestamp"') for line in lines)
    assert any(line.startswith(b"CONN ") for line in lines)
    assert any(line.startswith(b"kernel:") for line in lines)
    assert any(not line.strip() for line in lines)
    assert any(b"\xff\xfe\x80" in line for line in lines)
    assert any(b"999.10.2.300" in line for line in lines)


def test_attack_kinds_are_recorded(tmp_path: Path) -> None:
    _generate(tmp_path)
    kinds = {attack["kind"] for attack in _truth(tmp_path)}
    assert {"brute_force", "port_scan", "web_injection"} <= kinds


def test_ground_truth_matches_lines_written(tmp_path: Path) -> None:
    """Chaque ligne d'attaque annoncée existe, y compris une fois salie."""
    lines = _generate(tmp_path)
    expected: Counter[str] = Counter()
    for attack in _truth(tmp_path):
        if attack["kind"] != "mistype_decoy":
            expected[attack["ip"]] += attack["events"]

    found: Counter[str] = Counter()
    for line in lines:
        for address in IP_PATTERN.findall(line.decode("utf-8", errors="replace")):
            normalized = ".".join(str(int(part)) for part in address.split("."))
            if normalized in expected:
                found[normalized] += 1
    assert found == expected


def test_blacklist_partially_overlaps_attackers(tmp_path: Path) -> None:
    _generate(tmp_path)
    blacklist = set((tmp_path / "blacklist.txt").read_text(encoding="utf-8").split())
    assert len(blacklist) > 200
    attackers = {attack["ip"] for attack in _truth(tmp_path)}
    assert blacklist - attackers


def test_existing_logs_require_force(tmp_path: Path) -> None:
    arguments = ["--output", str(tmp_path), "--size-mb", "0.01"]
    assert main(arguments) == 0
    assert main(arguments) == 1
    assert main([*arguments, "--force"]) == 0


@pytest.mark.parametrize("arguments", [["--size-mb", "0"], ["--size-mb", "1", "--dirty-rate", "2"]])
def test_invalid_arguments_are_rejected(arguments: list[str]) -> None:
    with pytest.raises(SystemExit):
        main(arguments)
