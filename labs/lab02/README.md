# Лабораторна робота №2

**Тема:** Розробка консольних утиліт для задач кібербезпеки
**Студент:** Кузюк Максим Ярославович, група КБ-203
**Варіант:** 12 — «Аналізатор заголовків електронної пошти та фішингових індикаторів»

## 1. Встановлення залежностей

Усі команди виконуються **з кореня репозиторію** `cybersecurity-python-labs/`:

```bash
source .venv/bin/activate          # середовище з ЛР №1
pip install -r requirements.txt    # ruff, tabulate
```

## 2. Структура файлів

```
labs/lab02/
├── __init__.py
├── main.py                 # єдина точка входу: команди demo та analyze
├── task1.py                # Завдання 1: User, Admin, Session, AuditLog, UserAccount
├── task2.py                # Завдання 2: утиліта варіанта 12
├── README.md
└── data/
    ├── _manifest.json
    └── data_v12/                      # каталог свого варіанта з lab2_data.zip
        ├── mail_headers.log           # ВХІД: дамп поштових заголовків
        ├── suspicious_keywords.txt    # ВХІД: словник стоп-слів
        ├── phishing_report.csv        # ВИХІД (генерується)
        └── phishing_report.json       # ВИХІД (генерується)
```

### Вхідні файли варіанта 12

**`data/data_v12/mail_headers.log`** — текстовий дамп: листи розділені рядком
`--- MESSAGE ---`, у кожному блоці заголовки у вигляді `Назва: значення`
(`Message-ID`, `From`, `Return-Path`, `Reply-To`, `Received` — може повторюватись,
`Subject`). Приклад одного блоку:

```
Message-ID: <002@example.invalid>
From: Security Team <security@example.com>
Return-Path: <bounce@mailer.example.com>
Reply-To: support@evil-example.invalid
Received: from relay1.example.net by mx.example.net
Received: from relay2.example.net by relay1.example.net
Received: from unknown-host.example.invalid by relay2.example.net
Subject: URGENT: Verify your account immediately
```

**`data/data_v12/suspicious_keywords.txt`** — по одному стоп-слову або словосполученню
на рядок (рядки з `#` — коментарі): `urgent`, `verify your account`,
`password expired`, `reset now`, `payment required`, `confidential`.

## 3. Запуск

### Завдання 1 — демонстрація ООП

```bash
python -m labs.lab02.main demo
```

Сценарій послідовно показує: створення `User` і встановлення пароля (PBKDF2),
невдалий та успішний вхід, зміну `email` із валідацією через `@property`,
права `Admin`, завершення сеансу за таймаутом, доступ через `account["user"]`,
`logout()`, блокування входу деактивованого користувача та вміст `AuditLog`.

### Завдання 2 — аналіз поштових заголовків

```bash
# з типовими шляхами (data/data_v12/) → CSV-звіт
python -m labs.lab02.main analyze

# явні шляхи, JSON-звіт, детальне логування
python -m labs.lab02.main analyze \
    --mail-log labs/lab02/data/data_v12/mail_headers.log \
    --suspicious-keywords labs/lab02/data/data_v12/suspicious_keywords.txt \
    --out-csv labs/lab02/data/data_v12/phishing_report.json \
    --hop-threshold 3 --debug

# утиліту можна запускати й окремо від main.py
python -m labs.lab02.task2 --mail-log labs/lab02/data/data_v12/mail_headers.log
```

## 4. Параметри CLI утиліти (`analyze`)

| Параметр | Тип | Типове значення | Призначення |
|---|---|---|---|
| `--mail-log` | шлях | `data/data_v12/mail_headers.log` | дамп заголовків; суфікс `.json` читається як масив об'єктів, інакше — блоковий формат |
| `--suspicious-keywords` | шлях | `data/data_v12/suspicious_keywords.txt` | словник стоп-слів для `Subject` |
| `--out-csv` | шлях | `data/data_v12/phishing_report.csv` | файл звіту; суфікс `.json` → повний JSON (summary + листи), інакше CSV по листах |
| `--hop-threshold` | int > 0 | `3` | скільки вузлів `Received` вважається нормою |
| `--debug` | прапорець | вимкнено | рівень логування `DEBUG` замість `INFO` |

Усі аргументи необов'язкові — без них утиліта працює з файлами свого варіанта.
Типи (`Path`, `int`) перевіряє сам `argparse`, тому до тіла програми некоректне
значення не доходить.

## 5. Логіка оцінювання підозрілості

| Індикатор | Як перевіряється | Бали |
|---|---|---|
| Невідповідність домену `From` ↔ `Return-Path` | `re` + порівняння основного домену | +30 |
| Невідповідність домену `From` ↔ `Reply-To` | те саме | +30 |
| Стоп-слова в `Subject` | `re` зі словником (без регістру) | +10 за слово, максимум 25 |
| Аномальна кількість вузлів `Received` | `> --hop-threshold` | +20 |

Сума обрізається до 100. Рівні ризику: `CRITICAL` ≥ 70, `HIGH` ≥ 50,
`MEDIUM` ≥ 30, `LOW` ≥ 1, інакше `CLEAN`. Домени порівнюються за **основним**
доменом (дві останні мітки), тому легітимний `bounce@mailer.example.com` для
`security@example.com` не вважається підміною — підозрілим є лише вихід за межі
домену організації.

## 6. Результат на даних варіанта 12

```
[INFO] Analyzing email headers dump from .../data_v12/mail_headers.log...
[INFO] Total emails inspected: 6.
[WARNING] High-risk email 002@example.invalid from security@example.com (score 50)
[WARNING] High-risk email 004@example.invalid from helpdesk@example.com (score 100)
[WARNING] High-risk email 006@example.invalid from payroll@example.com (score 80)
[INFO] Phishing audit summary exported to .../data_v12/phishing_report.json

=== Phishing & Spoofing Audit Results ===
[CRITICAL RISK] Email ID #004@example.invalid | Subject: "Password expired - reset now"
  - Sender Mismatch  : From: "helpdesk@example.com" vs Return-Path: "notifications@updates.example.invalid"
  - Reply-To Mismatch: "password-reset@updates.example.invalid"
  - Stopwords Found  : ['password expired', 'reset now']
  - Hop Count        : 4 intermediate relays (Abnormal)
  - Risk Score       : 100/100 (CRITICAL)
[CRITICAL RISK] Email ID #006@example.invalid | Subject: "CONFIDENTIAL: payment required today"
  - Sender Mismatch  : From: "payroll@example.com" vs Return-Path: "payroll@billing-example.invalid"
  - Reply-To Mismatch: "payroll@billing-example.invalid"
  - Stopwords Found  : ['payment required', 'confidential']
  - Hop Count        : 1 intermediate relays
  - Risk Score       : 80/100 (CRITICAL)
[HIGH RISK] Email ID #002@example.invalid | Subject: "URGENT: Verify your account immediately"
  - Reply-To Mismatch: "support@evil-example.invalid"
  - Stopwords Found  : ['urgent', 'verify your account']
  - Hop Count        : 3 intermediate relays
  - Risk Score       : 50/100 (HIGH)

=== Risk Distribution ===
CRITICAL : 2
HIGH     : 1
CLEAN    : 3
```

### Пояснення знайдених аномалій

* **#004 (100/100)** — класичний фішинг зі скиданням пароля: `From` від
  `helpdesk@example.com`, але і конверт (`Return-Path`), і адреса відповіді ведуть
  на сторонній `updates.example.invalid`; у темі два стоп-слова; 4 вузли `Received`,
  усі в чужому домені — ознака маршруту через інфраструктуру атакуючого.
* **#006 (80/100)** — BEC-схема «оплата сьогодні»: домен відправника підмінений на
  схожий `billing-example.invalid` (typosquatting), `Reply-To` веде туди ж.
* **#002 (50/100)** — `Return-Path` легітимний (`mailer.example.com` — субдомен
  `example.com`), але `Reply-To` перенаправляє відповіді на `evil-example.invalid`:
  саме туди потрапили б введені користувачем дані.
* **#001, #003, #005** — узгоджені домени, короткий маршрут, нейтральні теми → `CLEAN`.

## 7. Поведінка при помилках

| Ситуація | Реакція | Код виходу |
|---|---|---|
| немає файлу `--mail-log` / `--suspicious-keywords` | `[ERROR] Файл ... не знайдено: <шлях>` | 1 |
| порожній словник стоп-слів | `[ERROR] Словник стоп-слів порожній: <шлях>` | 1 |
| некоректний JSON у вхідному файлі | `[ERROR] Некоректний JSON у <шлях>: ...` | 1 |
| у файлі немає жодного листа | `[ERROR] У файлі ... не знайдено жодного листа` | 1 |
| немає прав на запис звіту | `[ERROR] Не вдалося записати звіт у <шлях>: ...` | 1 |
| `--hop-threshold 0` або від'ємний | `[ERROR] --hop-threshold має бути додатним числом` | 2 |
| `--hop-threshold abc` | повідомлення `argparse` про `invalid int value` | 2 |
| команду не вказано | `usage:` та перелік `{demo,analyze}` | 2 |

Жодна з цих ситуацій не призводить до трасування стека — усі помилки вхідних
даних збираються у власний виняток `MailLogError` і виводяться через `logging`.

## 8. Класи Завдання 1

```
UserAccount  (композиція, "Has-A")
 ├── user      : User | Admin
 ├── session   : Session | None
 └── audit_log : AuditLog ──► list[AuditRecord]  (@dataclass(frozen=True))

User  ◄── Admin  (наслідування, "Is-A": + permissions)
```

* **Інкапсуляція.** `__password_hash` і `__password_salt` — приватні (name mangling
  `_User__password_hash`), доступні лише методам `set_password()` / `check_password()`.
  Пароль зберігається як `hashlib.pbkdf2_hmac("sha256", ...)` з окремою сіллю
  `os.urandom(16)` та `PBKDF2_ITERATIONS = 240_000`; перевірка — через
  `hmac.compare_digest()`. Через `__getitem__` хеш і сіль недоступні.
* **Наслідування (Is-A).** `Admin` — це теж користувач, тому успадковує `User`,
  викликає `super().__init__()` і лише додає `permissions` (змінювана колекція
  не є типовим аргументом — типове значення `None`).
* **Композиція (Has-A).** `UserAccount` не «є» користувачем, а *має* користувача,
  сеанс і журнал — тому об'єкти передаються в конструктор. Це дозволяє замінити
  сеанс (`account["session"] = Session(...)`) без зміни класу користувача.
* **`@dataclass` для аудиту.** `AuditRecord` — лише три поля без логіки, тому
  `@dataclass(frozen=True)` безкоштовно дає `__init__`, `__repr__`, `__eq__`
  та незмінність (запис аудиту не можна підправити після факту), а
  `field(default_factory=utc_now)` ставить час UTC автоматично.
* **Час.** Усюди `datetime.now(timezone.utc)`; `Session.is_active(timeout_sec)`
  порівнює простій із `timedelta`, відхиляючи непозитивний `timeout_sec`.
  `SESSION_TIMEOUT_SEC = 900`; `is_authenticated()` не викликає `touch()`,
  тому невдала перевірка не подовжує сеанс.
* **`__getitem__` / `__setitem__`** працюють лише з ключами `user`, `session`,
  `audit_log`: невідомий ключ → `KeyError`, невідповідний тип → `TypeError`.

## 9. Контроль якості коду

```bash
ruff check .          # All checks passed!
ruff format --check . # 14 files already formatted
```

Виявлені та усунені категорії: `I001` (несортовані імпорти), `UP024`
(`IOError` як псевдонім `OSError`), `UP012` (зайвий `encoding="utf-8"` в `encode()`),
`DTZ005` (`datetime.now()` без часового поясу), `TRY201` (`raise e` замість `raise`),
`TRY004` (`ValueError` там, де очікується `TypeError`), `RUF012` (змінюване типове
значення атрибута класу → `typing.ClassVar`), `F841` (невикористана змінна),
`BLE001` (перехоплення «сліпого» `Exception`).
