"""Завдання 1. Модель користувача, безпечної сесії та журналу аудиту.

Демонструє інкапсуляцію (приватні __password_hash / __password_salt),
наслідування (Admin -> User), композицію (UserAccount має User, Session,
AuditLog) та спеціальні методи (__str__, __getitem__, __setitem__).
"""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import ClassVar

PBKDF2_ITERATIONS = 240_000
SALT_BYTES = 16
SESSION_TIMEOUT_SEC = 900

EMAIL_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"


def utc_now() -> datetime:
    """Поточний час у UTC з часовим поясом (без неоднозначності)."""
    return datetime.now(timezone.utc)


class User:
    """Звичайний користувач системи.

    Пароль ніколи не зберігається у відкритому вигляді: тримаємо лише
    PBKDF2-HMAC-SHA256 похідну та індивідуальну випадкову сіль.
    """

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ) -> None:
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username має бути непорожнім рядком")
        self.username = username.strip()
        self.email = email  # через @property -> валідація
        self.role = role
        self.active = bool(active)
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_RE.fullmatch(value.strip()):
            raise ValueError(f"Некоректний формат email: {value!r}")
        self._email = value.strip()

    def set_password(self, password: str) -> None:
        """Обчислює та зберігає PBKDF2-похідну пароля з новою сіллю."""
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком")
        salt = os.urandom(SALT_BYTES)
        self.__password_salt = salt
        self.__password_hash = self.__derive(password, salt)

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль у постійному часі через hmac.compare_digest()."""
        if self.__password_hash is None or self.__password_salt is None:
            return False
        if not isinstance(password, str):
            return False
        candidate = self.__derive(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    @staticmethod
    def __derive(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def has_password(self) -> bool:
        return self.__password_hash is not None

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return f"User(username={self.username}, email={self.email}, role={self.role}, {state})"


class Admin(User):
    """Адміністратор: той самий користувач ("Is-A") плюс набір дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "admin",
        active: bool = True,
        permissions: set[str] | None = None,
    ) -> None:
        super().__init__(username, email, role, active)
        # Змінювану колекцію не ставимо типовим аргументом.
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("Дозвіл має бути непорожнім рядком")
        self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "-"
        state = "active" if self.active else "inactive"
        return (
            f"Admin(username={self.username}, email={self.email}, "
            f"role={self.role}, {state}, permissions=[{perms}])"
        )


class Session:
    """Сеанс користувача з контролем часу неактивності."""

    def __init__(self, ip: str, login_time: datetime | None = None) -> None:
        if not isinstance(ip, str) or not IPV4_RE.fullmatch(ip.strip()):
            raise ValueError(f"Некоректна IPv4-адреса сеансу: {ip!r}")
        self.ip = ip.strip()
        self.login_time = login_time or utc_now()
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновлює мітку останньої активності."""
        self.last_activity = utc_now()

    def is_active(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        if not isinstance(timeout_sec, int) or isinstance(timeout_sec, bool):
            raise TypeError("timeout_sec має бути цілим числом")
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        return utc_now() - self.last_activity < timedelta(seconds=timeout_sec)

    def idle_seconds(self) -> float:
        return (utc_now() - self.last_activity).total_seconds()

    def __str__(self) -> str:
        return (
            f"Session(ip={self.ip}, login={self.login_time:%Y-%m-%d %H:%M:%S} UTC, "
            f"idle={self.idle_seconds():.1f}s)"
        )


@dataclass(frozen=True)
class AuditRecord:
    """Один незмінний запис аудиту: коли, хто, що зробив."""

    username: str
    action: str
    timestamp: datetime = field(default_factory=utc_now)

    def __str__(self) -> str:
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S} UTC] {self.username:<12} {self.action}"


class AuditLog:
    """Журнал подій безпеки. Паролі в журнал не потрапляють."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> AuditRecord:
        record = AuditRecord(username=username, action=action)
        self._records.append(record)
        return record

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def show_all(self) -> None:
        if not self._records:
            print("  (журнал аудиту порожній)")
            return
        for record in self._records:
            print(f"  {record}")

    def __len__(self) -> int:
        return len(self._records)


class UserAccount:
    """Композиція ("Has-A"): обліковий запис = користувач + сеанс + аудит."""

    _ALLOWED_KEYS: ClassVar[dict[str, type]] = {
        "user": User,
        "session": Session,
        "audit_log": AuditLog,
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("user має бути екземпляром User")
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Створює сеанс лише після успішної перевірки активності та пароля."""
        if username != self.user.username or not self.user.active:
            self.audit_log.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        if not self.user.check_password(password):
            self.audit_log.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        self.session = Session(ip=ip)
        self.session.touch()
        self.audit_log.add_log(username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        """Перевірка сеансу, яка НЕ подовжує його час життя."""
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> bool:
        if self.session is None:
            return False
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_LOGOUT)
        return True

    def __getitem__(self, key: str):
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий ключ облікового запису: {key!r}")
        return getattr(self, key)

    def __setitem__(self, key: str, value) -> None:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий ключ облікового запису: {key!r}")
        expected = self._ALLOWED_KEYS[key]
        if key == "session" and value is None:
            self.session = None
            return
        if not isinstance(value, expected):
            raise TypeError(
                f"Для ключа {key!r} очікувався тип {expected.__name__}, "
                f"отримано {type(value).__name__}"
            )
        setattr(self, key, value)

    def __str__(self) -> str:
        session_info = str(self.session) if self.session else "no session"
        return f"UserAccount({self.user.username}, {session_info}, audit={len(self.audit_log)})"
