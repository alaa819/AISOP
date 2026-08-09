import json

from app.config.settings import APPLICATION_NAME, APPLICATION_VERSION
from app.core.parser import LogParser
from app.core.detector import DetectionEngine
from app.core.analyzer import SecurityAnalyzer
from app.database.schema import initialize_database
from app.database.repository import AlertRepository


def main():
    print("=" * 70)
    print(f"{APPLICATION_NAME} Security Operations Platform")
    print(f"Version: {APPLICATION_VERSION}")
    print("=" * 70)

    # ------------------------------------------------------------------
    # DATABASE INITIALIZATION
    # ------------------------------------------------------------------

    initialize_database()

    alert_repository = AlertRepository()

    # ------------------------------------------------------------------
    # AISOP COMPONENTS
    # ------------------------------------------------------------------

    parser = LogParser()
    detector = DetectionEngine()
    analyzer = SecurityAnalyzer()

    # ------------------------------------------------------------------
    # LOG PARSING
    # ------------------------------------------------------------------

    print("\n[1] Reading Linux logs...")

    parsed_logs = parser.parse()

    print(f"[+] Parsed events: {len(parsed_logs)}")

    # ------------------------------------------------------------------
    # DETECTION
    # ------------------------------------------------------------------

    print("\n[2] Running detection rules...")

    alerts = detector.detect(parsed_logs)

    print(f"[+] Alerts generated: {len(alerts)}")

    # ------------------------------------------------------------------
    # SECURITY ANALYSIS
    # ------------------------------------------------------------------

    print("\n[3] Running security analysis...")

    analyses = [
        analyzer.analyze(alert)
        for alert in alerts
    ]

    print(f"[+] Alerts analyzed: {len(analyses)}")

    # ------------------------------------------------------------------
    # PERSIST ALERTS
    # ------------------------------------------------------------------

    print("\n[4] Persisting security alerts...")

    stored_alerts = 0

    for analysis in analyses:
        alert = analysis["alert"]

        # Add the analysis assessment to the alert before persistence.
        alert["analysis"] = analysis.get("assessment")

        alert_repository.create_alert(alert)

        stored_alerts += 1

    print(f"[+] Alerts stored in database: {stored_alerts}")

    # ------------------------------------------------------------------
    # DISPLAY RESULTS
    # ------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("AISOP RESULTS")
    print("=" * 70)

    for analysis in analyses:

        alert = analysis["alert"]

        print(
            f"\n[{alert['severity']}] "
            f"{alert['title']} "
            f"({alert['risk_score']}/100)"
        )

        print(f"Host: {alert.get('host', 'Unknown')}")
        print(f"Service: {alert.get('service', 'Unknown')}")
        print(f"Time: {alert.get('timestamp', 'Unknown')}")
        print(f"Assessment: {analysis['assessment']}")
        print(
            f"Recommendation: "
            f"{alert.get('recommendation', 'No recommendation')}"
        )

    print("\n" + "=" * 70)

    # ------------------------------------------------------------------
    # MACHINE-READABLE OUTPUT
    # ------------------------------------------------------------------

    with open(
        "aisop_output.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            analyses,
            file,
            indent=4,
            default=str,
        )

    print("JSON output written to aisop_output.json")

    # ------------------------------------------------------------------
    # DATABASE SUMMARY
    # ------------------------------------------------------------------

    total_alerts = alert_repository.count_alerts()

    print(f"Total alerts stored in database: {total_alerts}")


if __name__ == "__main__":
    main()