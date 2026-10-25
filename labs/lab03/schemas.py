from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN


class CategoryCreate(BaseModel):
    """Тіло запиту на створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія у відповіді: разом зі створеним базою id."""

    id: int = Field(gt=0)


class RecordCreate(BaseModel):
    """Тіло запиту на створення запису (id не задається - його створює база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=VALUE_MIN, le=VALUE_MAX, allow_inf_nan=False)
    status: Literal["new", "in_progress", "done"]


class RecordReplace(RecordCreate):
    """Тіло запиту PUT: усі змінювані поля обов'язкові, як і в RecordCreate."""


class RecordRead(RecordCreate):
    """Запис у відповіді: id і category_name разом з усіма змінюваними полями."""

    id: int = Field(gt=0)
    category_name: str


RecordBatch = Annotated[list[RecordCreate], Field(min_length=1, max_length=100)]
