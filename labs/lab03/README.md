# Лабораторна робота 3 - Облік використання сховищ (варіант 12)

Web API на FastAPI поверх бази SQLite. Сервіс зберігає навчальні виміри
заповнення сховищ.

- Категорії сховищ: `logs`, `backups`, `archive`.
- `value` - частка зайнятого простору у відсотках (одиниця: `percent`,
  діапазон 0-100 включно).
- `status` - стан опрацювання запису: `new`, `in_progress`, `done`.
- Навчальний поріг реагування: `85.0`.

Константи варіанта винесено в `config.py`; робота з базою - через модуль
`sqlite3` без ORM, усі значення передаються параметрами SQL.

## Структура

```
labs/lab03/
  config.py          # константи варіанта: одиниця, поріг, межі value
  database.py        # з'єднання (PRAGMA foreign_keys=ON) і створення схеми
  schema.sql         # готова схема таблиць categories і records
  seed.py            # початкове заповнення бази в одній транзакції
  repository.py      # параметризовані SQL-операції
  schemas.py         # Pydantic-моделі запитів і відповідей
  main.py            # FastAPI-застосунок, lifespan, службові маршрути
  routers/           # APIRouter для categories і records
  data/seed.json     # початкові дані варіанта (у Git)
  data/lab3.sqlite3  # робоча база (НЕ у Git, створюється локально)
```

Робочий файл `data/lab3.sqlite3` до репозиторію не входить - він відтворюється
зі `schema.sql` і `seed.json`.

## Встановлення залежностей

З кореня репозиторію, у віртуальному середовищі з Python 3.10 або новішим:

```bash
pip install -r requirements.txt
```

## Початкове заповнення бази

```bash
python -m labs.lab03.seed
```

Створює таблиці (якщо їх немає) і додає 3 категорії та 8 записів в одній
транзакції. Повторний запуск непорожньої бази нічого не дублює.

## Запуск API

```bash
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

- Swagger UI: http://127.0.0.1:8000/docs
- OpenAPI-схема: http://127.0.0.1:8000/openapi.json

Режим `--reload` призначений для розроблення.

## Приклади запитів

```bash
# службові
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/student"

# список категорій
curl -i "http://127.0.0.1:8000/categories"

# список записів із фільтрами та пагінацією
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"

# створення запису (повертає 201, created id і category_name)
curl -i -X POST "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d '{"code":"V12-09","title":"Вимірювання сховища 09","category_id":1,"value":55.5,"status":"new"}'

# один запис, повна заміна (PUT - усі п'ять полів), видалення
curl -i "http://127.0.0.1:8000/records/1"
curl -i -X PUT "http://127.0.0.1:8000/records/1" \
  -H "Content-Type: application/json" \
  -d '{"code":"V12-01","title":"Вимірювання сховища 01","category_id":2,"value":70.0,"status":"done"}'
curl -i -X DELETE "http://127.0.0.1:8000/records/1"

# пакетне створення в одній транзакції (усе або нічого)
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V12-20","title":"Вимірювання сховища 20","category_id":1,"value":10.0,"status":"new"},{"code":"V12-21","title":"Вимірювання сховища 21","category_id":2,"value":20.0,"status":"new"}]'
```

Приклад скасування пакета: якщо другий елемент має `code`, що вже є в базі,
відповідь буде `409 Conflict`, і жоден елемент пакета не збережеться.

## HTTP-коди

- `200` - успішне отримання або оновлення
- `201` - успішне створення
- `204` - успішне видалення (без тіла)
- `404` - запис або потрібна категорія не існує
- `409` - дублікат унікального значення або категорія містить записи
- `422` - дані не відповідають моделі чи обмеженням параметрів

## Перевірка стилю

```bash
ruff check labs/lab03
ruff format --check labs/lab03
```
