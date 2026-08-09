import sqlite3
from pathlib import Path

from app.config.settings import BASE_DIR


DATABASE_DIR = BASE_DIR / "data"
DATABASE_PATH = DATABASE_DIR / "aisop.db"


def get_connection() -> sqlite3.Connection:
    """
    Create and return a SQLite database connection.

    SQLite creates the database file automatically if it does not
    already exist.
    """

    DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection