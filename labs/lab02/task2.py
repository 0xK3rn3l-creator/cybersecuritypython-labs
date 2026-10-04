"""Завдання 2 (варіант 12). Аналізатор заголовків електронної пошти
та індикаторів фішингу.

Утиліта читає дамп поштових заголовків (From, Return-Path, Reply-To,
Received, Subject), перевіряє невідповідність домену відправника,
шукає стоп-слова в темі листа, рахує кількість проміжних вузлів
ретрансляції та формує звіт з оцінкою підозрілості.
"""

import argparse
import csv
import json
import logging
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

LOGGER_NAME = "lab02.phishing_audit"
logger = logging.getLogger(LOGGER_NAME)

MESSAGE_SEPARATOR_RE = re.compile(r"^-{2,}\s*MESSAGE\s*-{2,}\s*$", re.MULTILINE)
HEADER_LINE_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9-]*)\s*:\s*(?P<value>.*)$")
EMAIL_ADDR_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?"
)
RECEIVED_FROM_RE = re.compile(
    r"\bfrom\s+(?P<host>[A-Za-z0-9._\-\[\]:]+)", re.IGNORECASE
)

# Ваги індикаторів підозрілості (сума обрізається до 100).
SCORE_RETURN_PATH_MISMATCH = 30
SCORE_REPLY_TO_MISMATCH = 30
SCORE_PER_STOPWORD = 10
SCORE_STOPWORD_CAP = 25
SCORE_ABNORMAL_HOPS = 20
MAX_SCORE = 100

DEFAULT_HOP_THRESHOLD = 3

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_CLEAN = "CLEAN"

RISK_THRESHOLDS = (
    (70, RISK_CRITICAL),
    (50, RISK_HIGH),
    (30, RISK_MEDIUM),
    (1, RISK_LOW),
)

CSV_COLUMNS = (
    "message_id",
    "subject",
    "from_address",
    "from_domain",
    "return_path",
    "reply_to",
    "return_path_mismatch",
    "reply_to_mismatch",
    "stopwords",
    "hop_count",
    "abnormal_hops",
    "risk_score",
    "risk_level",
)


class MailLogError(Exception):
    """Помилка читання або розбору вхідних даних утиліти."""


@dataclass
class EmailHeaders:
    """Сирі заголовки одного листа з дампу."""

    message_id: str = ""
    sender: str = ""
    return_path: str = ""
    reply_to: str = ""
    subject: str = ""
    received: list[str] = field(default_factory=list)


@dataclass
class EmailVerdict:
    """Результат аудиту одного листа."""

    message_id: str
    subject: str
    from_address: str
    from_domain: str
    return_path: str
    reply_to: str
    return_path_mismatch: bool
    reply_to_mismatch: bool
    stopwords: list[str]
    hop_count: int
    abnormal_hops: bool
    risk_score: int
    risk_level: str

    @property
    def is_suspicious(self) -> bool:
        return self.risk_score > 0


def configure_logging(debug: bool = False) -> None:
    """Налаштовує вивід логів у форматі [LEVEL] message."""
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        root.addHandler(handler)
    for handler in root.handlers:
        handler.setLevel(level)
    logger.setLevel(level)


def extract_address(raw_value: str) -> str:
    """Дістає чисту адресу з конструкцій типу 'Name <user@host>'."""
    match = EMAIL_ADDR_RE.search(raw_value or "")
    return match.group(0).lower() if match else ""


def domain_of(address: str) -> str:
    """Домен адреси (частина після @) у нижньому регістрі."""
    _, _, domain = address.partition("@")
    return domain.strip().strip(">").lower()


def registrable_domain(domain: str) -> str:
    """Спрощений 'основний' домен: дві останні мітки (sub.a.com -> a.com)."""
    labels = [label for label in domain.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def read_keywords(path: Path) -> list[str]:
    """Читає словник стоп-слів: по одному на рядок, # — коментар."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise MailLogError(f"Файл стоп-слів не знайдено: {path}") from exc
    except OSError as exc:
        raise MailLogError(f"Не вдалося прочитати {path}: {exc}") from exc

    keywords = []
    for line in text.splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("#"):
            keywords.append(candidate.lower())
    if not keywords:
        raise MailLogError(f"Словник стоп-слів порожній: {path}")
    logger.debug("Loaded %d suspicious keywords from %s", len(keywords), path)
    return keywords


def _parse_header_block(block: str) -> EmailHeaders | None:
    """Перетворює текстовий блок заголовків на EmailHeaders."""
    headers = EmailHeaders()
    found = False
    for line in block.splitlines():
        match = HEADER_LINE_RE.match(line.strip())
        if not match:
            continue
        name = match.group("name").lower()
        value = match.group("value").strip()
        found = True
        if name == "message-id":
            headers.message_id = value.strip("<>")
        elif name == "from":
            headers.sender = value
        elif name == "return-path":
            headers.return_path = value
        elif name == "reply-to":
            headers.reply_to = value
        elif name == "subject":
            headers.subject = value
        elif name == "received":
            headers.received.append(value)
    return headers if found else None


def parse_mail_log(path: Path) -> list[EmailHeaders]:
    """Розбирає дамп заголовків (.log — блоки, .json — список об'єктів)."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise MailLogError(f"Файл з заголовками не знайдено: {path}") from exc
    except OSError as exc:
        raise MailLogError(f"Не вдалося прочитати {path}: {exc}") from exc

    if path.suffix.lower() == ".json":
        return _parse_json_dump(text, path)

    blocks = MESSAGE_SEPARATOR_RE.split(text)
    if len(blocks) == 1:
        # Запасний варіант: листи розділені порожнім рядком.
        blocks = re.split(r"\n\s*\n", text)

    messages = []
    for index, block in enumerate(blocks, start=1):
        headers = _parse_header_block(block)
        if headers is None:
            logger.debug("Block #%d has no recognizable headers, skipped", index)
            continue
        if not headers.message_id:
            headers.message_id = f"msg-{index:03d}"
        messages.append(headers)

    if not messages:
        raise MailLogError(f"У файлі {path} не знайдено жодного листа")
    return messages


def _parse_json_dump(text: str, path: Path) -> list[EmailHeaders]:
    """Читає альтернативний формат: JSON-масив об'єктів із заголовками."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MailLogError(f"Некоректний JSON у {path}: {exc}") from exc
    if isinstance(payload, dict):
        payload = payload.get("emails", payload.get("messages", []))
    if not isinstance(payload, list):
        raise MailLogError(f"Очікувався масив листів у {path}")

    messages = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            logger.warning("Element #%d in %s is not an object, skipped", index, path)
            continue
        lowered = {str(key).lower(): value for key, value in item.items()}
        received = lowered.get("received", [])
        if isinstance(received, str):
            received = [received]
        messages.append(
            EmailHeaders(
                message_id=str(
                    lowered.get("message-id") or lowered.get("id") or f"msg-{index:03d}"
                ).strip("<>"),
                sender=str(lowered.get("from", "")),
                return_path=str(lowered.get("return-path", "")),
                reply_to=str(lowered.get("reply-to", "")),
                subject=str(lowered.get("subject", "")),
                received=[str(entry) for entry in received],
            )
        )
    if not messages:
        raise MailLogError(f"У файлі {path} не знайдено жодного листа")
    return messages


def find_stopwords(subject: str, keywords: list[str]) -> list[str]:
    """Шукає стоп-слова в темі листа (без урахування регістру)."""
    lowered = (subject or "").lower()
    hits = []
    for keyword in keywords:
        pattern = r"\b" + r"\s+".join(re.escape(part) for part in keyword.split())
        if re.search(pattern, lowered):
            hits.append(keyword)
    return hits


def count_hops(received: list[str]) -> int:
    """Кількість проміжних вузлів ретрансляції в заголовках Received."""
    hosts = []
    for entry in received:
        match = RECEIVED_FROM_RE.search(entry)
        hosts.append(match.group("host").lower() if match else entry.strip().lower())
    return len(hosts)


def risk_level_for(score: int) -> str:
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return RISK_CLEAN


def analyze_message(
    headers: EmailHeaders,
    keywords: list[str],
    hop_threshold: int = DEFAULT_HOP_THRESHOLD,
) -> EmailVerdict:
    """Оцінює один лист за чотирма групами індикаторів фішингу."""
    from_address = extract_address(headers.sender)
    return_path = extract_address(headers.return_path)
    reply_to = extract_address(headers.reply_to)

    from_domain = registrable_domain(domain_of(from_address))
    return_domain = registrable_domain(domain_of(return_path))
    reply_domain = registrable_domain(domain_of(reply_to))

    return_mismatch = bool(
        from_domain and return_domain and from_domain != return_domain
    )
    reply_mismatch = bool(from_domain and reply_domain and from_domain != reply_domain)

    stopwords = find_stopwords(headers.subject, keywords)
    hop_count = count_hops(headers.received)
    abnormal_hops = hop_count > hop_threshold

    score = 0
    if return_mismatch:
        score += SCORE_RETURN_PATH_MISMATCH
    if reply_mismatch:
        score += SCORE_REPLY_TO_MISMATCH
    score += min(len(stopwords) * SCORE_PER_STOPWORD, SCORE_STOPWORD_CAP)
    if abnormal_hops:
        score += SCORE_ABNORMAL_HOPS
    score = min(score, MAX_SCORE)

    verdict = EmailVerdict(
        message_id=headers.message_id,
        subject=headers.subject,
        from_address=from_address,
        from_domain=from_domain,
        return_path=return_path,
        reply_to=reply_to,
        return_path_mismatch=return_mismatch,
        reply_to_mismatch=reply_mismatch,
        stopwords=stopwords,
        hop_count=hop_count,
        abnormal_hops=abnormal_hops,
        risk_score=score,
        risk_level=risk_level_for(score),
    )
    logger.debug(
        "Message %s scored %d (%s)", verdict.message_id, score, verdict.risk_level
    )
    return verdict


def analyze_messages(
    messages: list[EmailHeaders],
    keywords: list[str],
    hop_threshold: int = DEFAULT_HOP_THRESHOLD,
) -> list[EmailVerdict]:
    return [analyze_message(msg, keywords, hop_threshold) for msg in messages]


def build_summary(verdicts: list[EmailVerdict], hop_threshold: int) -> dict:
    """Агрегована статистика звіту (collections.Counter)."""
    risk_counter = Counter(verdict.risk_level for verdict in verdicts)
    stopword_counter = Counter(
        word for verdict in verdicts for word in verdict.stopwords
    )
    sender_domains = Counter(
        verdict.from_domain for verdict in verdicts if verdict.from_domain
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_emails": len(verdicts),
        "suspicious_emails": sum(1 for verdict in verdicts if verdict.is_suspicious),
        "hop_threshold": hop_threshold,
        "risk_distribution": dict(risk_counter),
        "return_path_mismatches": sum(1 for v in verdicts if v.return_path_mismatch),
        "reply_to_mismatches": sum(1 for v in verdicts if v.reply_to_mismatch),
        "abnormal_hop_counts": sum(1 for v in verdicts if v.abnormal_hops),
        "top_stopwords": stopword_counter.most_common(5),
        "sender_domains": dict(sender_domains),
    }


def print_report(verdicts: list[EmailVerdict], summary: dict) -> None:
    """Виводить консольний звіт у форматі з методичних вказівок."""
    print("\n=== Phishing & Spoofing Audit Results ===")
    risky = sorted(
        (verdict for verdict in verdicts if verdict.is_suspicious),
        key=lambda verdict: verdict.risk_score,
        reverse=True,
    )
    if not risky:
        print("Підозрілих листів не виявлено.")
    for verdict in risky:
        print(
            f"[{verdict.risk_level} RISK] Email ID #{verdict.message_id} | "
            f'Subject: "{verdict.subject}"'
        )
        if verdict.return_path_mismatch:
            print(
                f'  - Sender Mismatch  : From: "{verdict.from_address}" '
                f'vs Return-Path: "{verdict.return_path}"'
            )
        if verdict.reply_to_mismatch:
            print(f'  - Reply-To Mismatch: "{verdict.reply_to}"')
        if verdict.stopwords:
            print(f"  - Stopwords Found  : {verdict.stopwords}")
        hops_note = " (Abnormal)" if verdict.abnormal_hops else ""
        print(
            f"  - Hop Count        : {verdict.hop_count} intermediate relays{hops_note}"
        )
        print(f"  - Risk Score       : {verdict.risk_score}/100 ({verdict.risk_level})")

    print("\n=== Risk Distribution ===")
    for level in (RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_CLEAN):
        count = summary["risk_distribution"].get(level, 0)
        if count:
            print(f"{level:<9}: {count}")

    if summary["top_stopwords"]:
        print("\n=== Top Subject Stopwords ===")
        for word, count in summary["top_stopwords"]:
            print(f"{word:<22}: {count}")


def _verdict_row(verdict: EmailVerdict) -> dict:
    row = asdict(verdict)
    row["stopwords"] = "; ".join(verdict.stopwords)
    return {column: row[column] for column in CSV_COLUMNS}


def save_report(verdicts: list[EmailVerdict], summary: dict, output: Path) -> None:
    """Зберігає звіт: .json — повний звіт, інше — CSV по листах."""
    output = output.expanduser()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix.lower() == ".json":
            payload = {
                "summary": summary,
                "emails": [asdict(verdict) for verdict in verdicts],
            }
            output.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        else:
            with output.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
                writer.writeheader()
                for verdict in verdicts:
                    writer.writerow(_verdict_row(verdict))
    except OSError as exc:
        raise MailLogError(f"Не вдалося записати звіт у {output}: {exc}") from exc
    logger.info("Phishing audit summary exported to %s", output)


def add_arguments(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Описує CLI-аргументи утиліти варіанта 12."""
    data_dir = Path(__file__).resolve().parent / "data" / "data_v12"
    parser.add_argument(
        "--mail-log",
        type=Path,
        default=data_dir / "mail_headers.log",
        help="шлях до дампу поштових заголовків (.log або .json)",
    )
    parser.add_argument(
        "--suspicious-keywords",
        type=Path,
        default=data_dir / "suspicious_keywords.txt",
        help="шлях до словника стоп-слів (по одному на рядок)",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=data_dir / "phishing_report.csv",
        help="шлях до звіту; суфікс .json зберігає JSON, інакше CSV",
    )
    parser.add_argument(
        "--hop-threshold",
        type=int,
        default=DEFAULT_HOP_THRESHOLD,
        help=f"максимальна нормальна кількість вузлів Received (дефолт: {DEFAULT_HOP_THRESHOLD})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="детальне логування (рівень DEBUG)",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    """Точка входу утиліти: повертає код завершення процесу."""
    configure_logging(getattr(args, "debug", False))
    if args.hop_threshold <= 0:
        logger.error("--hop-threshold має бути додатним числом")
        return 2
    try:
        logger.info("Analyzing email headers dump from %s...", args.mail_log)
        messages = parse_mail_log(args.mail_log)
        keywords = read_keywords(args.suspicious_keywords)
        logger.info("Total emails inspected: %d.", len(messages))

        verdicts = analyze_messages(messages, keywords, args.hop_threshold)
        summary = build_summary(verdicts, args.hop_threshold)
        print_report(verdicts, summary)

        critical = [v for v in verdicts if v.risk_level in (RISK_CRITICAL, RISK_HIGH)]
        for verdict in critical:
            logger.warning(
                "High-risk email %s from %s (score %d)",
                verdict.message_id,
                verdict.from_address,
                verdict.risk_score,
            )
        save_report(verdicts, summary, args.out_csv)
    except MailLogError as exc:
        logger.error("%s", exc)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.task2",
        description="Варіант 12: аналізатор заголовків пошти та фішингових індикаторів",
    )
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
