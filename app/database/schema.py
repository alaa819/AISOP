from app.database.connection import get_connection


CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    host TEXT,
    service TEXT,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    recommendation TEXT,
    source_ip TEXT,
    raw_event TEXT,
    analysis TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


CREATE_ALERTS_INDEXES = [
    """
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON alerts(timestamp);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts(severity);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_alerts_rule_id
    ON alerts(rule_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
    ON alerts(source_ip);
    """,
]


CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


CREATE_USERS_INDEXES = [
    """
    CREATE INDEX IF NOT EXISTS idx_users_username
    ON users(username);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_users_role
    ON users(role);
    """,
]


DEVELOPMENT_USERS = [
    {
        "username": "ala",
        "password_hash": (
            "$argon2id$v=19$m=65536,t=3,p=4$Esfn4mMaTRG26+pzg70Zhw$"
            "MO6Y8vfFcXKcEGCfauVoJJ0ealpdDsSpdiDi0cejxlI"
        ),
        "role": "ADMIN",
    },
    {
        "username": "analyst",
        "password_hash": (
            "$argon2id$v=19$m=65536,t=3,p=4$GWgvlCmlEtnZmYM8pD1urQ$"
            "vtYX4loCj0CFYdRgxvorNzuhXzOEmJdO/hBWm/PvlGY"
        ),
        "role": "ANALYST",
    },
    {
        "username": "viewer",
        "password_hash": (
            "$argon2id$v=19$m=65536,t=3,p=4$gsH+ypBjwMfBkrdc3yxvPA$"
            "7KvZ2ZUqC+dsEo5aG1wl3+P/JGc0hG4xwaQaY+tofaM"
        ),
        "role": "VIEWER",
    },
]


def seed_development_users(connection) -> None:
    """
    Create development users if they do not already exist.

    Existing users are not overwritten.
    """

    for user in DEVELOPMENT_USERS:
        connection.execute(
            """
            INSERT OR IGNORE INTO users (
                username,
                password_hash,
                role
            )
            VALUES (?, ?, ?)
            """,
            (
                user["username"],
                user["password_hash"],
                user["role"],
            ),
        )


def initialize_database() -> None:
    """
    Create the AISOP database schema if it does not already exist.
    """

    connection = get_connection()

    try:
        connection.execute(CREATE_ALERTS_TABLE)

        for index_statement in CREATE_ALERTS_INDEXES:
            connection.execute(index_statement)

        connection.execute(CREATE_USERS_TABLE)

        for index_statement in CREATE_USERS_INDEXES:
            connection.execute(index_statement)

        seed_development_users(connection)

        connection.commit()

    finally:
        connection.close()