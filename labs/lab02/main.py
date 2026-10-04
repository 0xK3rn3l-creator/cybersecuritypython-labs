"""Лабораторна робота №2 — єдина точка входу.

Команди:
    python -m labs.lab02.main demo      — демонстрація ООП із Завдання 1
    python -m labs.lab02.main analyze   — утиліта варіанта 12 із Завдання 2
"""

import argparse
from datetime import timedelta

from labs.lab02 import task2
from labs.lab02.task1 import (
    SESSION_TIMEOUT_SEC,
    Admin,
    AuditLog,
    Session,
    User,
    UserAccount,
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

DEMO_PASSWORD = "S0C@Analyst#2026"
DEMO_IP = "192.168.1.105"
SEPARATOR = "=" * 70


def _header(title: str) -> None:
    print(f"\n{SEPARATOR}\n{title}\n{SEPARATOR}")


def demo_user_and_login() -> UserAccount:
    """Успішний і невдалий вхід, валідація email."""
    _header("1. КОРИСТУВАЧ, ХЕШУВАННЯ ПАРОЛЯ ТА ВХІД")

    user = User(username="m_kuzuk", email="m_kuzuk@example.com", role="analyst")
    user.set_password(DEMO_PASSWORD)
    print(f"Створено: {user}")
    print(
        f"Пароль встановлено: {user.has_password()} (у відкритому вигляді не зберігається)"
    )

    account = UserAccount(user=user, audit_log=AuditLog())

    print("\n--- Невдалий вхід (хибний пароль) ---")
    ok = account.login("m_kuzuk", "WrongPassword123", DEMO_IP)
    print(f"login() -> {ok}; is_authenticated() -> {account.is_authenticated()}")

    print("\n--- Успішний вхід ---")
    ok = account.login("m_kuzuk", DEMO_PASSWORD, DEMO_IP)
    print(f"login() -> {ok}; is_authenticated() -> {account.is_authenticated()}")
    print(f"Сеанс: {account['session']}")

    print("\n--- Зміна email із валідацією (@property) ---")
    user.email = "max_kuzuk@kb203.example.org"
    print(f"Новий email: {user.email}")
    for bad_email in ("1max@example.com", "ab@example.com", "max@localhost"):
        try:
            user.email = bad_email
        except ValueError as exc:
            print(f"  ValueError для {bad_email!r}: {exc}")

    return account


def demo_admin() -> Admin:
    """Наслідування та керування правами адміністратора."""
    _header("2. АДМІНІСТРАТОР (НАСЛІДУВАННЯ Admin -> User)")

    admin = Admin(username="sec_admin", email="sec_admin@example.com")
    admin.set_password("Adm1n@Lab02!")
    admin.grant_permission("audit.read")
    admin.grant_permission("users.manage")
    admin.grant_permission("firewall.edit")
    print(admin)
    print(f"has_permission('users.manage') -> {admin.has_permission('users.manage')}")
    admin.revoke_permission("firewall.edit")
    print(f"після revoke_permission('firewall.edit'): {admin}")
    print(f"has_permission('firewall.edit') -> {admin.has_permission('firewall.edit')}")
    print(f"isinstance(admin, User) -> {isinstance(admin, User)}")
    return admin


def demo_timeout_and_logout(account: UserAccount) -> None:
    """Завершення сеансу за таймаутом, __getitem__/__setitem__ та вихід."""
    _header("3. ТАЙМАУТ СЕАНСУ, ДОСТУП ПО КЛЮЧАХ ТА LOGOUT")

    session = account["session"]
    print(f"SESSION_TIMEOUT_SEC = {SESSION_TIMEOUT_SEC}")
    print(f"До таймауту: is_authenticated() -> {account.is_authenticated()}")

    # Імітуємо простій, довший за таймаут.
    session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 60)
    print(
        f"Простій {session.idle_seconds():.0f} c -> "
        f"is_authenticated() -> {account.is_authenticated()}"
    )
    print(
        "Невдала перевірка не подовжує сеанс: "
        f"is_authenticated() -> {account.is_authenticated()}"
    )

    session.touch()
    print(f"Після touch(): is_authenticated() -> {account.is_authenticated()}")

    print("\n--- __getitem__ / __setitem__ ---")
    print(f"account['user'] -> {account['user'].username}")
    account["session"] = Session(ip="10.0.0.42")
    print(f"account['session'] = Session('10.0.0.42') -> {account['session']}")
    for key in ("password_hash", "_User__password_salt"):
        try:
            account[key]
        except KeyError as exc:
            print(f"  KeyError для {key!r}: {exc}")
    try:
        account["user"] = "not-a-user"
    except TypeError as exc:
        print(f"  TypeError для account['user'] = 'not-a-user': {exc}")

    print("\n--- Вихід із системи ---")
    print(f"logout() -> {account.logout()}")
    print(f"is_authenticated() -> {account.is_authenticated()}")


def demo_deactivated_user(account: UserAccount) -> None:
    """Вхід деактивованого користувача неможливий."""
    _header("4. ДЕАКТИВАЦІЯ ОБЛІКОВОГО ЗАПИСУ")
    account["user"].deactivate()
    print(f"Після deactivate(): {account['user']}")
    print(f"login() -> {account.login('m_kuzuk', DEMO_PASSWORD, DEMO_IP)}")


def run_demo(_args: argparse.Namespace) -> int:
    """Сценарій демонстрації Завдання 1."""
    print(SEPARATOR)
    print(f"ЛР №2 | {STUDENT_NAME} | {GROUP_NAME} | варіант {VARIANT_NUMBER}")
    print(SEPARATOR)

    account = demo_user_and_login()
    demo_admin()
    demo_timeout_and_logout(account)
    demo_deactivated_user(account)

    _header("5. ЖУРНАЛ АУДИТУ (AuditLog, @dataclass AuditRecord)")
    account["audit_log"].show_all()
    print(f"\nУсього записів: {len(account['audit_log'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Лабораторна робота №2: ООП та CLI-утиліта кібербезпеки "
        f"(варіант {VARIANT_NUMBER})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser("demo", help="демонстрація класів Завдання 1")
    demo_parser.set_defaults(handler=run_demo)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Завдання 2: аналіз поштових заголовків на індикатори фішингу",
    )
    task2.add_arguments(analyze_parser)
    analyze_parser.set_defaults(handler=task2.run)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
