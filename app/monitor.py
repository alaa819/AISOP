import time
from pathlib import Path

from app.config.settings import LOG_FILE
from app.core.analyzer import SecurityAnalyzer
from app.core.detector import DetectionEngine
from app.core.parser import LogParser
from app.database.repository import AlertRepository
from app.database.schema import initialize_database


POLL_INTERVAL = 0.5


class LogMonitor:
    """
    Continuously watches the Linux syslog for new events.

    Only lines appended after the monitor starts are processed.
    Existing historical log entries are not replayed.
    """

    def __init__(self, log_file: Path = LOG_FILE):
        self.log_file = Path(log_file)
        self.detector = DetectionEngine()
        self.analyzer = SecurityAnalyzer()
        self.repository = AlertRepository()

    def parse_line(self, line: str) -> dict[str, str] | None:
        """
        Parse one syslog line using the same formats supported
        by the AISOP LogParser.
        """

        parts = line.split()

        if not parts:
            return None

        # Modern ISO 8601 / RFC 3339 syslog format.
        if "T" in parts[0] and len(parts) >= 4:
            timestamp = parts[0]
            host = parts[1]
            service = parts[2].rstrip(":")
            message = " ".join(parts[3:])

        # Traditional syslog format.
        elif len(parts) >= 6:
            timestamp = " ".join(parts[0:3])
            host = parts[3]
            service = parts[4].rstrip(":")
            message = " ".join(parts[5:])

        else:
            return None

        return {
            "timestamp": timestamp,
            "host": host,
            "service": service,
            "message": message,
            "raw": line.strip(),
        }

    def process_line(self, line: str) -> None:
        """
        Parse, detect, analyze, and persist a newly appended log line.
        """

        event = self.parse_line(line)

        if event is None:
            return

        alerts = self.detector.detect([event])

        for alert in alerts:
            analysis = self.analyzer.analyze(alert)

            alert_data = analysis["alert"]
            alert_data["analysis"] = analysis.get("assessment")

            self.repository.create_alert(alert_data)

            print(
                f"[ALERT] "
                f"{alert_data['severity']} | "
                f"{alert_data['title']} | "
                f"{alert_data.get('host', 'Unknown')} | "
                f"{alert_data.get('timestamp', 'Unknown')}",
                flush=True,
            )

    def run(self) -> None:
        """
        Follow the log file and process only newly appended lines.
        """

        print("=" * 70)
        print("AISOP Real-Time Log Monitor")
        print("=" * 70)
        print(f"Watching: {self.log_file}")
        print("Waiting for new security events...", flush=True)

        with self.log_file.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:

            # Start at the end so existing logs are not replayed.
            file.seek(0, 2)

            while True:
                line = file.readline()

                if line:
                    try:
                        self.process_line(line)
                    except Exception as error:
                        print(
                            f"[ERROR] Failed to process log line: {error}",
                            flush=True,
                        )
                else:
                    time.sleep(POLL_INTERVAL)


def main() -> None:
    initialize_database()

    monitor = LogMonitor()
    monitor.run()


if __name__ == "__main__":
    main()