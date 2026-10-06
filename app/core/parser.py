from pathlib import Path
from typing import List, Dict

from app.config.settings import LOG_FILE, MAX_LOG_LINES


class LogParser:
    """
    Converts raw Linux log lines into structured events.

    Supports:
    - Modern ISO 8601 / RFC 3339 syslog timestamps
    - Traditional syslog timestamps
    """

    def __init__(self, log_file: Path = LOG_FILE):
        self.log_file = Path(log_file)

    def read_raw_logs(self) -> List[str]:
        """
        Read the most recent log entries.
        """

        with self.log_file.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            return file.readlines()[-MAX_LOG_LINES:]

    def parse(self) -> List[Dict[str, str]]:
        """
        Convert raw log lines into structured dictionaries.
        """

        parsed_logs = []

        for line in self.read_raw_logs():
            parts = line.split()

            if not parts:
                continue

            # Modern syslog format:
            # 2026-10-05T21:59:31.656444+00:00 ala sshd[99999]:
            # Failed password ...
            if "T" in parts[0] and len(parts) >= 4:
                timestamp = parts[0]
                host = parts[1]
                service = parts[2].rstrip(":")
                message = " ".join(parts[3:])

            # Traditional syslog format:
            # Oct 5 21:59:31 ala sshd[99999]: Failed password ...
            elif len(parts) >= 6:
                timestamp = " ".join(parts[0:3])
                host = parts[3]
                service = parts[4].rstrip(":")
                message = " ".join(parts[5:])

            else:
                continue

            parsed_logs.append(
                {
                    "timestamp": timestamp,
                    "host": host,
                    "service": service,
                    "message": message,
                    "raw": line.strip(),
                }
            )

        return parsed_logs