from typing import Any

from app.database.connection import get_connection


class UserRepository:
    """
    Handles persistence and retrieval of AISOP users.
    """

    def get_user_by_username(
        self,
        username: str,
    ) -> dict[str, Any] | None:
        """
        Retrieve a user by username.
        """

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    role,
                    is_active,
                    created_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

            if row is None:
                return None

            return dict(row)

        finally:
            connection.close()

    def get_user_by_id(
        self,
        user_id: int,
    ) -> dict[str, Any] | None:
        """
        Retrieve a user by database ID.
        """

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    role,
                    is_active,
                    created_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

            if row is None:
                return None

            return dict(row)

        finally:
            connection.close()

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str,
    ) -> int:
        """
        Create a new user.
        """

        allowed_roles = {
            "ADMIN",
            "ANALYST",
            "VIEWER",
        }

        role = role.upper()

        if role not in allowed_roles:
            raise ValueError(
                "Invalid role. "
                "Use ADMIN, ANALYST, or VIEWER."
            )

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    role,
                ),
            )

            connection.commit()

            return int(cursor.lastrowid)

        finally:
            connection.close()

    def deactivate_user(
        self,
        user_id: int,
    ) -> bool:
        """
        Disable a user account.
        """

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                UPDATE users
                SET is_active = 0
                WHERE id = ?
                """,
                (user_id,),
            )

            connection.commit()

            return cursor.rowcount > 0

        finally:
            connection.close()

    def activate_user(
        self,
        user_id: int,
    ) -> bool:
        """
        Enable a user account.
        """

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                UPDATE users
                SET is_active = 1
                WHERE id = ?
                """,
                (user_id,),
            )

            connection.commit()

            return cursor.rowcount > 0

        finally:
            connection.close()

    def update_user_role(
        self,
        user_id: int,
        role: str,
    ) -> bool:
        """
        Change a user's role.
        """

        allowed_roles = {
            "ADMIN",
            "ANALYST",
            "VIEWER",
        }

        role = role.upper()

        if role not in allowed_roles:
            raise ValueError(
                "Invalid role. "
                "Use ADMIN, ANALYST, or VIEWER."
            )

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                UPDATE users
                SET role = ?
                WHERE id = ?
                """,
                (
                    role,
                    user_id,
                ),
            )

            connection.commit()

            return cursor.rowcount > 0

        finally:
            connection.close()