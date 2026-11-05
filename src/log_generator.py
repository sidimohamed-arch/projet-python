"""Générateur de faux logs système et réseau volumineux.

Les lignes sont produites une par une et écrites en flux : la mémoire utilisée
ne dépend pas de la taille demandée. Le format est décrit dans docs/format_logs.md.

Exemple :
    python -m src.log_generator --output data/raw --size-gb 12
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

MIB = 1024**2
GIB = 1024**3

# (niveau, ip, port, protocole, utilisateur, catégorie, événement, payload)
Event = tuple[str, str, int, str, str, str, str, str]

DEFAULT_START = datetime(2026, 10, 1, tzinfo=timezone.utc)
BASE_GAP_MS = 5
MAX_ACTIVE_ATTACKS = 8
STEP_PROBABILITY_PER_ATTACK = 0.04

# Intensité du trafic selon l'heure UTC : creux la nuit, pic en journée.
HOUR_FACTORS = (
    0.3, 0.2, 0.2, 0.2, 0.2, 0.3, 0.5, 0.8, 1.2, 1.5, 1.6, 1.6,
    1.4, 1.5, 1.6, 1.6, 1.5, 1.3, 1.1, 0.9, 0.8, 0.7, 0.5, 0.4,
)  # fmt: skip

PATHS = (
    "/", "/index.html", "/login", "/logout", "/api/v1/users", "/api/v1/orders",
    "/api/v1/products", "/api/v1/search", "/admin", "/static/app.js",
    "/static/style.css", "/health", "/metrics", "/checkout", "/profile",
)  # fmt: skip
METHODS = ("GET",) * 7 + ("POST",) * 2 + ("PUT",)
STATUS_CODES = (
    (200,) * 78 + (201,) * 3 + (301,) * 3 + (304,) * 5 + (400,) * 2
    + (401,) * 2 + (403,) * 1 + (404,) * 4 + (500,) * 1 + (503,) * 1
)  # fmt: skip
TARGET_USERS = ("admin", "root", "test", "oracle", "postgres", "deploy")
SCANNED_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 3306, 3389, 5432, 8080)
INJECTION_PATHS = (
    "/search?q=' OR '1'='1",
    "/login?user=admin'--",
    "/products?id=1; DROP TABLE users",
    "/../../etc/passwd",
    "/static/..%2f..%2fwindows/win.ini",
)
SYSTEM_MESSAGES = (
    ("INFO", "BOOT_OK", "kernel: démarrage terminé en 12.4s"),
    ("INFO", "SERVICE_OK", "systemd: nginx.service actif"),
    ("INFO", "BACKUP_OK", "backup: sauvegarde quotidienne réussie (42 Go)"),
    ("WARNING", "DISK_HIGH", "disk: /var utilisé à 87%"),
    ("WARNING", "CPU_HIGH", "cpu: charge moyenne 9.2 sur 8 coeurs"),
    ("ERROR", "SERVICE_DOWN", "systemd: échec de redis.service"),
    ("CRITICAL", "OUT_OF_MEMORY", "kernel: out of memory, processus 4412 tué"),
)
APP_MESSAGES = (
    ("ERROR", "EXCEPTION", 'ValueError: invalid literal for int() with base 10: "abc"'),
    ("ERROR", "EXCEPTION", "KeyError: 'customer_id' dans orders.create"),
    ("ERROR", "TIMEOUT", "TimeoutError: service paiement sans réponse après 30s"),
    ("WARNING", "RETRY", "nouvelle tentative 3/5 vers le service stock"),
    ("CRITICAL", "DATA_LOSS", "file de messages perdue, 120 événements non traités"),
)
RAW_LINES = (
    "kernel: eth0 link up 1000Mbps",
    "cron[2211]: tâche logrotate terminée",
    "sshd[913]: Server listening on 0.0.0.0 port 22",
    "ntpd: horloge synchronisée, décalage 0.002s",
)
LEVEL_VARIANTS = {
    "INFO": ("info", "Info", "INF"),
    "WARNING": ("warning", "Warning", "WARN"),
    "ERROR": ("error", "Error", "ERR"),
    "CRITICAL": ("critical", "Critical", "CRIT"),
}


@dataclass(frozen=True)
class GeneratorConfig:
    """Paramètres d'une génération."""

    output_dir: Path
    total_bytes: int
    file_bytes: int = 256 * MIB
    seed: int = 42
    start: datetime = DEFAULT_START
    attacks_per_10k: float = 0.5
    dirty_rate: float = 0.05


@dataclass
class Attack:
    """Attaque injectée dans les logs : sert de vérité terrain au détecteur."""

    kind: str
    ip: str
    user: str
    start: str = ""
    end: str = ""
    events: int = 0
    complete: bool = False
    details: dict[str, Any] = field(default_factory=dict)


class LogStream:
    """Produit un flux infini de lignes de logs, sous forme de bytes."""

    def __init__(self, config: GeneratorConfig, on_attack: Callable[[Attack], None]) -> None:
        self._rng = random.Random(config.seed)
        self._on_attack = on_attack
        self._attack_probability = config.attacks_per_10k / 10_000
        self._dirty_rate = config.dirty_rate
        self._ms = int(config.start.timestamp() * 1000)
        self._second = -1
        self._second_text = ""
        self._factor = 1.0
        self._ts = ""
        self._active: list[tuple[Attack, Iterator[Event]]] = []

        seen: set[str] = set()
        self.clients = self._make_ips(20_000, 0.7, seen)
        self.hostiles = self._make_ips(500, 0.0, seen)
        self.ghosts = self._make_ips(200, 0.0, seen)
        self._servers = tuple(f"10.0.0.{host}" for host in range(1, 31))
        self._users = tuple(f"u{number:05d}" for number in range(1, 5001))
        self._generators: tuple[Callable[[], Event], ...] = (
            (self._web,) * 45
            + (self._auth,) * 20
            + (self._database,) * 10
            + (self._firewall,) * 12
            + (self._system,) * 8
            + (self._app,) * 5
        )
        self._recoverable: tuple[Callable[[list[str]], None], ...] = (
            self._vary_level,
            self._pad_fields,
            self._vary_user,
            self._lower_protocol,
            self._space_timestamp,
            self._french_timestamp,
            self._zero_pad_ip,
        )
        self._invalid: tuple[Callable[[str, list[str]], bytes], ...] = (
            self._empty_line,
            self._blank_line,
            self._comment_line,
            self._rotation_banner,
            self._truncate,
            self._invalid_ip,
            self._invalid_port,
            self._unknown_level,
            self._invalid_date,
            self._missing_field,
            self._broken_json,
            self._invalid_bytes,
            self._duplicate,
            self._garbage,
        )

    def _make_ips(self, count: int, private_share: float, seen: set[str]) -> tuple[str, ...]:
        """Tire des adresses uniques, privées ou publiques, de façon reproductible."""
        ips: list[str] = []
        randint = self._rng.randint
        while len(ips) < count:
            if self._rng.random() < private_share:
                ip = f"192.168.{randint(0, 255)}.{randint(1, 254)}"
            else:
                first = randint(11, 223)
                if first in (127, 169, 172, 192):
                    continue
                ip = f"{first}.{randint(0, 255)}.{randint(0, 255)}.{randint(1, 254)}"
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return tuple(ips)

    def blacklist(self) -> list[str]:
        """Retourne une blacklist qui ne recoupe que partiellement les IP actives."""
        known = list(self.hostiles[: len(self.hostiles) * 6 // 10])
        return sorted(known + list(self.ghosts) + list(self.clients[:5]))

    def lines(self) -> Iterator[bytes]:
        """Génère les lignes indéfiniment, attaques et saletés comprises."""
        random_value = self._rng.random
        while True:
            self._tick()
            if len(self._active) < MAX_ACTIVE_ATTACKS and random_value() < self._attack_probability:
                self._start_attack()
            event = self._next_attack_event()
            protected = event is not None
            if event is None:
                event = self._pick(self._generators)()
            line = self._render(event, protected)
            if random_value() < self._dirty_rate:
                yield from self._dirty(line, protected)
            else:
                yield line.encode("utf-8")

    def flush_attacks(self) -> None:
        """Signale les attaques encore en cours à la fin de la génération."""
        for attack, _ in self._active:
            self._on_attack(attack)
        self._active.clear()

    def _pick(self, items: Sequence[Any]) -> Any:
        return items[int(self._rng.random() * len(items))]

    def _tick(self) -> None:
        self._ms += 1 + int(self._rng.random() * 2 * BASE_GAP_MS / self._factor)
        second, millis = divmod(self._ms, 1000)
        if second != self._second:
            self._second = second
            moment = datetime.fromtimestamp(second, timezone.utc)
            self._second_text = moment.strftime("%Y-%m-%dT%H:%M:%S")
            self._factor = HOUR_FACTORS[moment.hour]
        self._ts = f"{self._second_text}.{millis:03d}Z"

    # ------------------------------------------------------------------ trafic normal

    def _web(self) -> Event:
        status = self._pick(STATUS_CODES)
        level = "INFO" if status < 400 else "WARNING" if status < 500 else "ERROR"
        size = int(self._rng.random() * 50_000)
        delay = 1 + int(self._rng.random() * 800)
        payload = (
            f'{{"method":"{self._pick(METHODS)}","path":"{self._pick(PATHS)}",'
            f'"status":{status},"bytes":{size},"ms":{delay}}}'
        )
        return (level, self._pick(self.clients), 443, "TCP", self._pick(self._users),
                "web", "HTTP_REQUEST", payload)  # fmt: skip

    def _auth(self) -> Event:
        ip = self._pick(self.clients)
        user = self._pick(self._users)
        roll = self._rng.random()
        if roll < 0.08:
            return ("WARNING", ip, 22, "TCP", user, "auth", "AUTH_FAILED",
                    '{"method":"ssh","reason":"bad_password"}')  # fmt: skip
        if roll < 0.75:
            return ("INFO", ip, 22, "TCP", user, "auth", "AUTH_SUCCESS", '{"method":"ssh"}')
        if roll < 0.97:
            return ("INFO", ip, 443, "TCP", user, "auth", "LOGOUT", '{"method":"oauth"}')
        return ("INFO", ip, 443, "TCP", user, "auth", "PASSWORD_RESET", '{"method":"email"}')

    def _database(self) -> Event:
        ip = self._pick(self._servers)
        delay = 1 + int(self._rng.random() * 200)
        roll = self._rng.random()
        if roll < 0.92:
            level, event, payload = "INFO", "QUERY_OK", f'{{"table":"orders","ms":{delay}}}'
        elif roll < 0.98:
            level, event, payload = "WARNING", "SLOW_QUERY", f'{{"table":"orders","ms":{delay + 5000}}}'
        elif roll < 0.995:
            level, event, payload = "ERROR", "DEADLOCK", '{"code":40001,"table":"users"}'
        else:
            level, event, payload = "CRITICAL", "CONNECTION_LOST", '{"code":57014}'
        return (level, ip, 5432, "TCP", "svc_db", "database", event, payload)

    def _firewall(self) -> Event:
        port = self._pick(SCANNED_PORTS)
        protocol = "UDP" if port == 53 else "TCP"
        size = int(self._rng.random() * 9000)
        if self._rng.random() < 0.85:
            level, event = "INFO", "CONN_ALLOWED"
        else:
            level, event = "WARNING", "CONN_BLOCKED"
        payload = f'{{"rule":"FW-{1 + int(self._rng.random() * 40):03d}","bytes":{size}}}'
        return (level, self._pick(self.clients), port, protocol, "-", "firewall", event, payload)

    def _system(self) -> Event:
        level, event, message = self._pick(SYSTEM_MESSAGES)
        return (level, self._pick(self._servers), 514, "UDP", "-", "system", event, message)

    def _app(self) -> Event:
        level, event, message = self._pick(APP_MESSAGES)
        return (level, self._pick(self._servers), 8080, "TCP", self._pick(self._users),
                "app", event, message)  # fmt: skip

    # ------------------------------------------------------------------ attaques

    def _start_attack(self) -> None:
        kinds: tuple[Callable[[Attack], Iterator[Event]], ...] = (
            self._brute_force, self._brute_force, self._mistype_decoy,
            self._port_scan, self._dos_burst, self._web_injection,
        )  # fmt: skip
        scenario = self._pick(kinds)
        busy = {attack.ip for attack, _ in self._active}
        pool = self.clients if scenario == self._mistype_decoy else self.hostiles
        ip = self._pick(pool)
        while ip in busy:
            ip = self._pick(pool)
        attack = Attack(scenario.__name__.lstrip("_"), ip, self._pick(TARGET_USERS))
        self._active.append((attack, scenario(attack)))

    def _next_attack_event(self) -> Event | None:
        """Fait avancer au hasard une attaque active pour l'entrelacer au trafic."""
        if not self._active:
            return None
        probability = min(0.5, STEP_PROBABILITY_PER_ATTACK * len(self._active))
        if self._rng.random() >= probability:
            return None
        index = int(self._rng.random() * len(self._active))
        attack, steps = self._active[index]
        event = next(steps, None)
        if event is None:
            attack.complete = True
            self._on_attack(attack)
            del self._active[index]
            return None
        attack.start = attack.start or self._ts
        attack.end = self._ts
        attack.events += 1
        return event

    def _brute_force(self, attack: Attack) -> Iterator[Event]:
        attempts = self._rng.randint(5, 30)
        attack.details["attempts"] = attempts
        attack.details["succeeded"] = self._rng.random() < 0.3
        for _ in range(attempts):
            yield ("WARNING", attack.ip, 22, "TCP", attack.user, "auth", "AUTH_FAILED",
                   '{"method":"ssh","reason":"bad_password"}')  # fmt: skip
        if attack.details["succeeded"]:
            yield ("INFO", attack.ip, 22, "TCP", attack.user, "auth", "AUTH_SUCCESS",
                   '{"method":"ssh"}')  # fmt: skip

    def _mistype_decoy(self, attack: Attack) -> Iterator[Event]:
        """Faux positif potentiel : quelques erreurs de saisie, puis une connexion réussie."""
        attempts = self._rng.randint(2, 3)
        attack.details["attempts"] = attempts
        for _ in range(attempts):
            yield ("WARNING", attack.ip, 22, "TCP", attack.user, "auth", "AUTH_FAILED",
                   '{"method":"ssh","reason":"bad_password"}')  # fmt: skip
        yield ("INFO", attack.ip, 22, "TCP", attack.user, "auth", "AUTH_SUCCESS",
               '{"method":"ssh"}')  # fmt: skip

    def _port_scan(self, attack: Attack) -> Iterator[Event]:
        attack.user = "-"
        first_port = self._rng.randint(1, 60_000)
        count = self._rng.randint(20, 100)
        attack.details["ports"] = count
        for port in range(first_port, first_port + count):
            yield ("WARNING", attack.ip, port, "TCP", "-", "firewall", "CONN_BLOCKED",
                   '{"rule":"FW-999","bytes":0}')  # fmt: skip

    def _dos_burst(self, attack: Attack) -> Iterator[Event]:
        attack.user = "-"
        path = self._pick(PATHS)
        count = self._rng.randint(100, 400)
        attack.details.update(path=path, requests=count)
        for _ in range(count):
            status = 503 if self._rng.random() < 0.4 else 200
            level = "ERROR" if status == 503 else "INFO"
            yield (level, attack.ip, 443, "TCP", "-", "web", "HTTP_REQUEST",
                   f'{{"method":"GET","path":"{path}","status":{status},"bytes":0,"ms":1}}')  # fmt: skip

    def _web_injection(self, attack: Attack) -> Iterator[Event]:
        attack.user = "-"
        count = self._rng.randint(3, 10)
        attack.details["requests"] = count
        for _ in range(count):
            path = self._pick(INJECTION_PATHS)
            yield ("WARNING", attack.ip, 443, "TCP", "-", "web", "HTTP_REQUEST",
                   f'{{"method":"GET","path":"{path}","status":403,"bytes":0,"ms":2}}')  # fmt: skip

    # ------------------------------------------------------------------ formats de sortie

    def _render(self, event: Event, protected: bool) -> str:
        level, ip, port, protocol, user, category, name, payload = event
        roll = self._rng.random()
        if roll < 0.06:
            structured = payload if payload.startswith("{") else json.dumps(payload, ensure_ascii=False)
            return (
                f'{{"timestamp":"{self._ts}","level":"{level}","ip":"{ip}","port":{port},'
                f'"protocol":"{protocol}","user":"{user}","category":"{category}",'
                f'"event":"{name}","payload":{structured}}}\n'
            )
        if category == "firewall" and roll < 0.30:
            return f"CONN {self._ts} {ip} {port} {protocol} {name}\n"
        if category in ("system", "app") and roll < 0.30 and not protected:
            return f"{self._pick(RAW_LINES)}\n"
        return f"{self._ts} | {level} | {ip}:{port}/{protocol} | {user} | {category} | {name} | {payload}\n"

    # ------------------------------------------------------------------ données sales

    def _dirty(self, line: str, protected: bool) -> Iterator[bytes]:
        """Salit une ligne. Une ligne d'attaque reste récupérable après nettoyage."""
        fields = line.rstrip("\n").split(" | ")
        if len(fields) != 7:
            yield f"  {line.rstrip()}  \n".encode()
            return
        if protected or self._rng.random() < 0.7:
            self._pick(self._recoverable)(fields)
            yield f"{' | '.join(fields)}\n".encode()
            return
        yield self._pick(self._invalid)(line, fields)

    def _vary_level(self, fields: list[str]) -> None:
        fields[1] = self._pick(LEVEL_VARIANTS[fields[1]])

    def _pad_fields(self, fields: list[str]) -> None:
        for index in (1, 3, 5):
            fields[index] = f"  {fields[index]}\t"

    def _vary_user(self, fields: list[str]) -> None:
        fields[3] = self._pick(("NULL", "N/A", "none")) if fields[3] == "-" else fields[3].upper()

    def _lower_protocol(self, fields: list[str]) -> None:
        fields[2] = fields[2].lower()

    def _space_timestamp(self, fields: list[str]) -> None:
        fields[0] = fields[0].replace("T", " ").removesuffix("Z")

    def _french_timestamp(self, fields: list[str]) -> None:
        moment = datetime.strptime(fields[0][:19], "%Y-%m-%dT%H:%M:%S")
        fields[0] = moment.strftime("%d/%m/%Y %H:%M:%S")

    def _zero_pad_ip(self, fields: list[str]) -> None:
        address, service = fields[2].split(":", 1)
        padded = ".".join(f"{int(part):03d}" for part in address.split("."))
        fields[2] = f"{padded}:{service}"

    def _empty_line(self, _line: str, _fields: list[str]) -> bytes:
        return b"\n"

    def _blank_line(self, _line: str, _fields: list[str]) -> bytes:
        return b"   \t  \n"

    def _comment_line(self, _line: str, _fields: list[str]) -> bytes:
        return b"# maintenance en cours, collecte partielle\n"

    def _rotation_banner(self, _line: str, _fields: list[str]) -> bytes:
        return f"---- log rotated at {self._ts} ----\n".encode()

    def _truncate(self, line: str, _fields: list[str]) -> bytes:
        return f"{line[: self._rng.randint(5, len(line) - 2)]}\n".encode()

    def _invalid_ip(self, _line: str, fields: list[str]) -> bytes:
        service = fields[2].split(":", 1)[1]
        fields[2] = f"{self._pick(('999.10.2.300', 'unknown', '10.0.0'))}:{service}"
        return f"{' | '.join(fields)}\n".encode()

    def _invalid_port(self, _line: str, fields: list[str]) -> bytes:
        address, service = fields[2].split(":", 1)
        protocol = service.split("/", 1)[1]
        fields[2] = f"{address}:{self._pick(('70000', '-1', 'abc'))}/{protocol}"
        return f"{' | '.join(fields)}\n".encode()

    def _unknown_level(self, _line: str, fields: list[str]) -> bytes:
        fields[1] = self._pick(("VERBOSE", "???", ""))
        return f"{' | '.join(fields)}\n".encode()

    def _invalid_date(self, _line: str, fields: list[str]) -> bytes:
        fields[0] = self._pick(("2026-13-45T25:61:00.000Z", "hier", "0000-00-00"))
        return f"{' | '.join(fields)}\n".encode()

    def _missing_field(self, _line: str, fields: list[str]) -> bytes:
        del fields[self._rng.randint(1, 5)]
        return f"{' | '.join(fields)}\n".encode()

    def _broken_json(self, _line: str, fields: list[str]) -> bytes:
        if fields[6].startswith("{"):
            fields[6] = fields[6][: len(fields[6]) // 2]
        else:
            fields[6] = '{"message": sans_guillemets'
        return f"{' | '.join(fields)}\n".encode()

    def _invalid_bytes(self, line: str, _fields: list[str]) -> bytes:
        return line[:30].encode() + b"\xff\xfe\x80" + line[30:].encode()

    def _duplicate(self, line: str, _fields: list[str]) -> bytes:
        return line.encode() * 2

    def _garbage(self, _line: str, _fields: list[str]) -> bytes:
        return b"#@!" * self._rng.randint(10, 1000) + b"\n"


def _remove_previous_run(output_dir: Path, force: bool) -> None:
    previous = list(output_dir.glob("app-*.log"))
    if previous and not force:
        raise FileExistsError(
            f"{len(previous)} fichier(s) app-*.log déjà présent(s) dans {output_dir} : utilisez --force"
        )
    for path in previous:
        path.unlink()


def _write_file(path: Path, lines: Iterator[bytes], target: int) -> int:
    size = 0
    log_file: BinaryIO
    with open(path, "wb", buffering=MIB) as log_file:
        for line in lines:
            log_file.write(line)
            size += len(line)
            if size >= target:
                break
    return size


def write_logs(config: GeneratorConfig, force: bool = False) -> tuple[int, int]:
    """Écrit les logs, la blacklist et la vérité terrain.

    Retourne le nombre d'octets de logs écrits et le nombre de fichiers créés.
    """
    config.output_dir.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(config.output_dir).free
    if free < config.total_bytes + GIB // 10:
        raise OSError(f"Espace disque insuffisant : {free / GIB:.1f} Gio disponibles")
    _remove_previous_run(config.output_dir, force)

    written = 0
    file_count = 0
    truth_path = config.output_dir / "ground_truth.jsonl"
    with open(truth_path, "w", encoding="utf-8", newline="\n") as truth:

        def record(attack: Attack) -> None:
            truth.write(json.dumps(asdict(attack), ensure_ascii=False) + "\n")

        stream = LogStream(config, record)
        lines = stream.lines()
        while written < config.total_bytes:
            file_count += 1
            path = config.output_dir / f"app-{file_count:04d}.log"
            written += _write_file(path, lines, min(config.file_bytes, config.total_bytes - written))
            print(f"{path.name} : {written / GIB:.2f} / {config.total_bytes / GIB:.2f} Gio", file=sys.stderr)
        stream.flush_attacks()

    blacklist_path = config.output_dir / "blacklist.txt"
    blacklist_path.write_text("\n".join(stream.blacklist()) + "\n", encoding="utf-8", newline="\n")
    return written, file_count


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Génère de faux logs volumineux et variés.")
    parser.add_argument("--output", type=Path, default=Path("data/raw"), help="dossier de sortie")
    size = parser.add_mutually_exclusive_group(required=True)
    size.add_argument("--size-gb", type=float, help="taille totale en Gio")
    size.add_argument("--size-mb", type=float, help="taille totale en Mio")
    parser.add_argument("--file-size-mb", type=int, default=256, help="taille de chaque fichier (Mio)")
    parser.add_argument("--seed", type=int, default=42, help="graine aléatoire")
    parser.add_argument("--attacks-per-10k", type=float, default=0.5, help="attaques pour 10 000 lignes")
    parser.add_argument("--dirty-rate", type=float, default=0.05, help="part de lignes salies (0 à 1)")
    parser.add_argument("--force", action="store_true", help="remplace les app-*.log existants")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée en ligne de commande."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    total_bytes = int(args.size_gb * GIB) if args.size_gb is not None else int(args.size_mb * MIB)
    if total_bytes <= 0 or args.file_size_mb <= 0:
        parser.error("les tailles doivent être strictement positives")
    if not 0 <= args.dirty_rate <= 1 or args.attacks_per_10k < 0:
        parser.error("--dirty-rate doit être entre 0 et 1, --attacks-per-10k positif")

    config = GeneratorConfig(
        output_dir=args.output,
        total_bytes=total_bytes,
        file_bytes=args.file_size_mb * MIB,
        seed=args.seed,
        attacks_per_10k=args.attacks_per_10k,
        dirty_rate=args.dirty_rate,
    )
    try:
        written, files = write_logs(config, force=args.force)
    except OSError as error:
        print(f"Erreur : {error}", file=sys.stderr)
        return 1
    print(f"{written / MIB:.1f} Mio écrits dans {files} fichier(s) : {config.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
