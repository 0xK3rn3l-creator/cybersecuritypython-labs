"""Спільне відображення помилок шару даних на HTTP-відповіді."""

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException, status

from labs.lab03.repository import NotFoundError

logger = logging.getLogger("labs.lab03")


@contextmanager
def repository_errors(conflict_detail: str) -> Iterator[None]:
    """Перетворити винятки шару даних на HTTPException із потрібним кодом."""
    try:
        yield
    except NotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(error)
        ) from error
    except sqlite3.IntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=conflict_detail
        ) from error
    except sqlite3.Error as error:
        logger.exception("Помилка бази даних")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Внутрішня помилка сервера.",
        ) from error
