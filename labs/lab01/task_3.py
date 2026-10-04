import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

from tabulate import tabulate

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

HASH_ALG = "md5"
MIN_PASSWORD_LEN = 8

SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

users_to_register = (
    ("admin_sec", "AdminPass123!"),
    ("dev_lead", "SecureDev#2026"),
    ("sec_analyst", "AnalyzeLogs88"),
    ("net_adm", "Router#Pass99"),
    ("qa_tester", "Test12345!"),
    ("auditor", "Audit#Pass2026"),
    ("ops_eng", "OpsEngine99"),
    ("crypto_user", "HashPass123"),
    ("cloud_admin", "CloudPass#2026"),
    ("guest_user", "GuestAccess8"),
)


class ValidationError(Exception):
    pass


def log_event(func):
    """Декоратор для логування спроб входу у JSON-файл."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if len(args) > 0 else kwargs.get("username", "unknown")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        try:
            result = func(*args, **kwargs)
            status = "success" if result else "failure"
        except Exception:
            status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": status,
                "timestamp": timestamp,
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            logs.append(log_entry)

            os.makedirs(DATA_DIR, exist_ok=True)
            try:
                with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except OSError as e:
                print(f"[ERROR] Помилка запису логу: {e}")

        return result

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Пароль або сіль не можуть бути порожніми!")

    if len(password) < MIN_PASSWORD_LEN:
        raise ValidationError(
            f"Пароль занадто короткий! Мінімальна довжина: {MIN_PASSWORD_LEN}"
        )

    salted_password = f"{password}{salt}".encode()
    return hashlib.md5(salted_password).hexdigest()


def create_user(username: str, password: str) -> tuple:
    hash_val = generate_hash(password, salt=SALT)
    return (username, hash_val)


def create_users(users_list: list | tuple) -> None:
    try:
        os.makedirs(DATA_DIR, exist_ok=True)

        with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])

            for u, p in users_list:
                try:
                    username, pwd_hash = create_user(u, p)
                    writer.writerow([username, pwd_hash])
                except (ValueError, ValidationError) as e:
                    print(f"[SKIP] Помилка створення користувача {u}: {e}")

    except OSError as e:
        print(f"[ERROR] Помилка доступу до файлу бази даних: {e}")
        raise


def read_users_db() -> list:

    users_db = []
    try:
        if not os.path.exists(USERS_CSV_PATH):
            raise FileNotFoundError(f"Файл {USERS_CSV_PATH} не знайдено!")

        with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader, None)  # пропускаємо рядок заголовків
            for row in reader:
                if row:
                    users_db.append((row[0], row[1]))
    except OSError as e:
        print(f"[ERROR] Помилка при читанні бази даних: {e}")
        raise

    return users_db


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми!")

    users_db = read_users_db()
    users_dict = dict(users_db)

    if username not in users_dict:
        return False

    try:
        input_hash = generate_hash(password, salt=SALT)
    except ValidationError:
        return False

    return users_dict[username] == input_hash


def print_task3_results(users_db: list) -> None:
    """Виводить список користувачів з CSV у вигляді таблиці."""
    print(
        f"=== Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER} ==="
    )
    print(
        f"Персональна сіль: '{SALT}' | Алгоритм: MD5 | Min length: {MIN_PASSWORD_LEN}\n"
    )
    print("--- БАЗА ДАНИХ КОРИСТУВАЧІВ (users.csv) ---")
    print(
        tabulate(
            users_db, headers=["Логін (Username)", "MD5 Хеш пароля"], tablefmt="grid"
        )
    )


if __name__ == "__main__":
    try:
        create_users(users_to_register)
        db_data = read_users_db()
        print_task3_results(db_data)

        print("\n--- Тестування автентифікації (login) ---")
        print("Успішний вхід (admin_sec):", login("admin_sec", "AdminPass123!"))
        print("Невірний пароль (admin_sec):", login("admin_sec", "WrongPass123"))
        print("Неіснуючий користувач:", login("unknown_user", "AdminPass123!"))
    except (OSError, ValueError, ValidationError) as err:
        print(f"[FATAL] Виникла помилка: {err}")
