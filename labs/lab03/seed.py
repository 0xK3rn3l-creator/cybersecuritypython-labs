import json
import sqlite3
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"

REQUIRED_CATEGORY_KEYS = {"id", "name"}
REQUIRED_RECORD_KEYS = {"code", "title", "category_id", "value", "status"}


def load_seed() -> dict:
    """Прочитати seed.json і структурно перевірити його вміст."""
    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("Корінь seed.json має бути об'єктом.")

    categories = data.get("categories")
    records = data.get("records")
    if not isinstance(categories, list) or not isinstance(records, list):
        raise TypeError("seed.json має містити списки categories і records.")

    for category in categories:
        if (
            not isinstance(category, dict)
            or not REQUIRED_CATEGORY_KEYS <= category.keys()
        ):
            raise ValueError("Кожна категорія має містити поля id і name.")
    for record in records:
        if not isinstance(record, dict) or not REQUIRED_RECORD_KEYS <= record.keys():
            raise ValueError(
                "Кожен запис має містити code, title, category_id, value і status."
            )
    return data


def is_empty(connection: sqlite3.Connection) -> bool:
    """Перевірити, чи база ще не містить категорій і записів."""
    categories = connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
    records = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    return categories == 0 and records == 0


def seed_database() -> None:
    """Заповнити порожню базу даними варіанта в межах однієї транзакції."""
    initialize_database()
    data = load_seed()

    with closing(get_connection()) as connection:
        if not is_empty(connection):
            print("База вже містить дані - повторне заповнення пропущено.")
            return

        with connection:
            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                [(item["id"], item["name"]) for item in data["categories"]],
            )
            connection.executemany(
                "INSERT INTO records (code, title, category_id, value, status) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        item["code"],
                        item["title"],
                        item["category_id"],
                        item["value"],
                        item["status"],
                    )
                    for item in data["records"]
                ],
            )

    print(
        f"Базу заповнено: {len(data['categories'])} категорії, "
        f"{len(data['records'])} записів."
    )


if __name__ == "__main__":
    try:
        seed_database()
    except (json.JSONDecodeError, TypeError, ValueError, sqlite3.Error) as error:
        print(f"Не вдалося заповнити базу, зміни скасовано: {error}")
