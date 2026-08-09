import json
from typing import Any

from app.database.connection import get_connection


class AlertRepository:
    """
    Handles persistence and retrieval of AISOP alerts.

    The rest of the application interacts with this repository
    rather than directly executing SQL statements.
    """

    def create_alert(self, alert: dict[str, Any]) -> int:
        """
        Store an alert and return its database ID.
        """

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO alerts (
                    timestamp,
                    host,
                    service,
                    rule_id,
                    title,
                    description,
                    severity,
                    risk_score,
                    recommendation,
                    source_ip,
                    raw_event,
                    analysis
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.get("timestamp"),
                    alert.get("host"),
                    alert.get("service"),
                    alert.get("rule_id"),
                    alert.get("title"),
                    alert.get("description"),
                    alert.get("severity"),
                    alert.get("risk_score"),
                    alert.get("recommendation"),
                    alert.get("source_ip"),
                    self._serialize(alert.get("raw_event")),
                    alert.get("analysis"),
                ),
            )

            connection.commit()

            return int(cursor.lastrowid)

        finally:
            connection.close()

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        """
        Retrieve a single alert by database ID.
        """

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT *
                FROM alerts
                WHERE id = ?
                """,
                (alert_id,),
            ).fetchone()

            if row is None:
                return None

            return dict(row)

        finally:
            connection.close()

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve alerts using pagination.
        """

        connection = get_connection()

        try:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()

    def get_alerts_by_severity(
        self,
        severity: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Retrieve alerts matching a severity level.
        """

        connection = get_connection()

        try:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                WHERE severity = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (severity, limit),
            ).fetchall()

            return [dict(row) for row in rows]

        finally:
            connection.close()

    def count_alerts(self) -> int:
        """
        Return the total number of stored alerts.
        """

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM alerts
                """
            ).fetchone()

            return int(row["total"])

        finally:
            connection.close()

    @staticmethod
    def _serialize(value: Any) -> str | None:
        """
        Convert structured event data into JSON before storage.
        """

        if value is None:
            return None

        if isinstance(value, str):
            return value

        return json.dumps(value, default=str)