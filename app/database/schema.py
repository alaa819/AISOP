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
    """
]


def initialize_database() -> None:
    """
    Create the AISOP database schema if it does not already exist.
    """

    connection = get_connection()

    try:
        connection.execute(CREATE_ALERTS_TABLE)

        for index_statement in CREATE_ALERTS_INDEXES:
            connection.execute(index_statement)

        connection.commit()

    finally:
        connection.close()