"""Маршрути записів: CRUD, фільтри, пагінація та пакетне додавання."""

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.routers import repository_errors
from labs.lab03.schemas import RecordBatch, RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["records"])


@router.get("", summary="Список записів із фільтрами", response_model=list[RecordRead])
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    status_param: Annotated[
        Literal["new", "in_progress", "done"] | None,
        Query(alias="status", description="Лише записи з цим статусом"),
    ] = None,
    min_value: Annotated[
        float | None, Query(ge=0, le=100, description="value >= min_value")
    ] = None,
    q: Annotated[
        str | None,
        Query(min_length=1, max_length=120, description="Буквальний підрядок у title"),
    ] = None,
    limit: Annotated[
        int, Query(ge=1, le=100, description="Максимум записів, типово 20")
    ] = 20,
    offset: Annotated[
        int, Query(ge=0, description="Кількість пропущених записів, типово 0")
    ] = 0,
) -> list[dict]:
    """Повернути записи за фільтрами (AND) з поділом на сторінки, сортовані за id."""
    return repository.list_records(
        category_id, status_param, min_value, q, limit, offset
    )


@router.post(
    "/bulk",
    summary="Пакетне створення записів",
    status_code=status.HTTP_201_CREATED,
    response_model=list[RecordRead],
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Категорію елемента не знайдено"},
        status.HTTP_409_CONFLICT: {"description": "Дублікат code у пакеті або в базі"},
    },
)
def create_records_bulk(payload: RecordBatch) -> list[dict]:
    """Додати пакет записів у межах однієї транзакції: усе або нічого."""
    with repository_errors("Дублікат code у пакеті або в базі."):
        return repository.add_records_bulk([item.model_dump() for item in payload])


@router.get(
    "/{record_id}",
    summary="Один запис",
    response_model=RecordRead,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Запис не знайдено"}},
)
def get_record(
    record_id: Annotated[int, Path(gt=0, description="Додатний id запису")],
) -> dict:
    """Повернути один запис за id."""
    record = repository.get_record_by_id(record_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Запис не знайдено."
        )
    return record


@router.post(
    "",
    summary="Створити запис",
    status_code=status.HTTP_201_CREATED,
    response_model=RecordRead,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Категорію не знайдено"},
        status.HTTP_409_CONFLICT: {"description": "Запис із таким code вже існує"},
    },
)
def create_record(payload: RecordCreate) -> dict:
    """Створити запис; id створює база."""
    with repository_errors("Запис із таким code вже існує."):
        return repository.add_record(payload.model_dump())


@router.put(
    "/{record_id}",
    summary="Повна заміна змінюваних полів запису",
    response_model=RecordRead,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Запис або категорію не знайдено"},
        status.HTTP_409_CONFLICT: {"description": "Запис із таким code вже існує"},
    },
)
def replace_record(
    record_id: Annotated[int, Path(gt=0, description="Додатний id запису")],
    payload: RecordReplace,
) -> dict:
    """Повністю замінити змінювані поля запису; id лишається незмінним."""
    with repository_errors("Запис із таким code вже існує."):
        return repository.update_record(record_id, payload.model_dump())


@router.delete(
    "/{record_id}",
    summary="Видалити запис",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={status.HTTP_404_NOT_FOUND: {"description": "Запис не знайдено"}},
)
def delete_record(
    record_id: Annotated[int, Path(gt=0, description="Додатний id запису")],
) -> None:
    """Видалити запис за id."""
    with repository_errors("Запис не можна видалити."):
        repository.delete_record(record_id)
