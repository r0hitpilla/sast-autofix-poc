"""Shared request dependencies: the database session."""

from collections.abc import Iterator

from sqlalchemy.orm import Session

from .db import make_sessionmaker

_sessionmaker = None


def get_session() -> Iterator[Session]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = make_sessionmaker()
    with _sessionmaker() as session:
        yield session
