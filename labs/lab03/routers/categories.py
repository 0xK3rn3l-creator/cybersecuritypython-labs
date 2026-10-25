"""Маршрути категорій сховищ."""

from typing import Annotated

from fastapi import APIRouter, Path, status

from labs.lab03 import repository
from labs.lab03.routers import repository_errors
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get("", summary="Список категорій", response_model=list[CategoryRead])
def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    summary="Створити категорію",
    status_code=status.HTTP_201_CREATED,
    response_model=CategoryRead,
    responses={status.HTTP_409_CONFLICT: {"description": "Назва категорії вже існує"}},
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити категорію; id створює база."""
    with repository_errors("Категорія з такою назвою вже існує."):
        return repository.create_category(payload.name)


@router.delete(
    "/{category_id}",
    summary="Видалити порожню категорію",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Категорію не знайдено"},
        status.HTTP_409_CONFLICT: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: Annotated[int, Path(gt=0, description="Додатний id категорії")],
) -> None:
    """Видалити категорію без записів; непорожню блокує цілісність даних."""
    with repository_errors("Категорія містить записи й не може бути видалена."):
        repository.delete_empty_category(category_id)
