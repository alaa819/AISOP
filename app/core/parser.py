from pathlib import Path
from typing import List, Dict

from app.config.settings import LOG_FILE, MAX_LOG_LINES


class LogParser:
    """
    Converts raw Linux log lines into structured events.
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

            if len(parts) < 6:
                continue

            parsed_logs.append(
                {
                    "timestamp": " ".join(parts[0:3]),
                    "host": parts[3],
                    "service": parts[4].rstrip(":"),
                    "message": " ".join(parts[5:]),
                    "raw": line.strip(),
                }
            )

        return parsed_logs