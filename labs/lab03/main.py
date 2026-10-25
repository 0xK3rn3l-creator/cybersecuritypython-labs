from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

TAGS_METADATA = [
    {
        "name": "service",
        "description": "Службові маршрути: доступність і дані студента.",
    },
    {"name": "categories", "description": "Категорії сховищ: logs, backups, archive."},
    {
        "name": "records",
        "description": "Виміри заповнення сховищ із фільтрами та пакетом.",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску, не заповнюючи базу даними."""
    initialize_database()
    yield


app = FastAPI(
    title="Облік використання сховищ",
    description=(
        "Навчальний сервіс ЛР 3 (варіант 12). Зберігає виміри заповнення "
        "сховищ: value - частка зайнятого простору у відсотках (одиниця: percent, "
        "діапазон 0-100 включно), навчальний поріг реагування - 85.0. "
        "Категорії сховищ: logs, backups, archive."
    ),
    version="1.0.0",
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["service"], summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    """Повернути ознаку, що сервіс працює."""
    return {"status": "ok"}


@app.get("/student", tags=["service"], summary="Дані студента")
def student() -> dict[str, object]:
    """Повернути ПІБ, групу та номер варіанта з shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
