import sqlite3
from contextlib import closing

from labs.lab03.database import get_connection


class NotFoundError(Exception):
    """Потрібного id (запису чи категорії) не існує."""


_RECORD_SELECT = """
    SELECT
        records.id,
        records.code,
        records.title,
        records.category_id,
        records.value,
        records.status,
        categories.name AS category_name
    FROM records
    JOIN categories ON categories.id = records.category_id
"""


def _open() -> sqlite3.Connection:
    """Відкрити з'єднання з рядками як словникоподібні sqlite3.Row."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    """Перевірити наявність категорії в межах наданого з'єднання."""
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    return row is not None


def _get_record(connection: sqlite3.Connection, record_id: int) -> dict | None:
    """Прочитати один запис разом із category_name або повернути None."""
    row = connection.execute(
        _RECORD_SELECT + " WHERE records.id = ?", (record_id,)
    ).fetchone()
    return dict(row) if row else None


# --- Категорії -------------------------------------------------------------


def create_category(name: str) -> dict:
    """Створити категорію; id створює база."""
    with closing(_open()) as connection:
        with connection:
            cursor = connection.execute(
                "INSERT INTO categories (name) VALUES (?)", (name,)
            )
        row = connection.execute(
            "SELECT id, name FROM categories WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        return dict(row)


def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    with closing(_open()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def delete_empty_category(category_id: int) -> None:
    """Видалити порожню категорію; непорожню блокує FOREIGN KEY RESTRICT."""
    with closing(_open()) as connection:
        if not _category_exists(connection, category_id):
            raise NotFoundError(f"Категорію {category_id} не знайдено.")
        with connection:
            connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))


# --- Записи ----------------------------------------------------------------


def add_record(data: dict) -> dict:
    """Додати запис і повернути його разом із category_name."""
    with closing(_open()) as connection:
        if not _category_exists(connection, data["category_id"]):
            raise NotFoundError(f"Категорію {data['category_id']} не знайдено.")
        with connection:
            cursor = connection.execute(
                "INSERT INTO records (code, title, category_id, value, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    data["code"],
                    data["title"],
                    data["category_id"],
                    data["value"],
                    data["status"],
                ),
            )
        return _get_record(connection, cursor.lastrowid)


def get_record_by_id(record_id: int) -> dict | None:
    """Повернути один запис за id або None."""
    with closing(_open()) as connection:
        return _get_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Повернути записи за фільтрами з поділом на сторінки, сортовані за id."""
    clauses: list[str] = []
    params: list[object] = []
    if category_id is not None:
        clauses.append("records.category_id = ?")
        params.append(category_id)
    if status is not None:
        clauses.append("records.status = ?")
        params.append(status)
    if min_value is not None:
        clauses.append("records.value >= ?")
        params.append(min_value)
    if q is not None:
        clauses.append("instr(records.title, ?) > 0")
        params.append(q)

    sql = _RECORD_SELECT
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY records.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(_open()) as connection:
        rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]


def update_record(record_id: int, data: dict) -> dict:
    """Повністю оновити змінювані поля запису; id лишається незмінним."""
    with closing(_open()) as connection:
        if _get_record(connection, record_id) is None:
            raise NotFoundError(f"Запис {record_id} не знайдено.")
        if not _category_exists(connection, data["category_id"]):
            raise NotFoundError(f"Категорію {data['category_id']} не знайдено.")
        with connection:
            connection.execute(
                "UPDATE records SET code = ?, title = ?, category_id = ?, "
                "value = ?, status = ? WHERE id = ?",
                (
                    data["code"],
                    data["title"],
                    data["category_id"],
                    data["value"],
                    data["status"],
                    record_id,
                ),
            )
        return _get_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис за id; відсутній id дає NotFoundError."""
    with closing(_open()) as connection:
        if _get_record(connection, record_id) is None:
            raise NotFoundError(f"Запис {record_id} не знайдено.")
        with connection:
            connection.execute("DELETE FROM records WHERE id = ?", (record_id,))


def add_records_bulk(records: list[dict]) -> list[dict]:
    """Додати пакет записів у межах однієї транзакції: усе або нічого."""
    with closing(_open()) as connection:
        for data in records:
            if not _category_exists(connection, data["category_id"]):
                raise NotFoundError(f"Категорію {data['category_id']} не знайдено.")
        new_ids: list[int] = []
        with connection:
            for data in records:
                cursor = connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        data["code"],
                        data["title"],
                        data["category_id"],
                        data["value"],
                        data["status"],
                    ),
                )
                new_ids.append(cursor.lastrowid)
        return [_get_record(connection, record_id) for record_id in new_ids]
