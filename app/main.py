import json

from app.config.settings import APPLICATION_NAME, APPLICATION_VERSION
from app.core.parser import LogParser
from app.core.detector import DetectionEngine
from app.core.analyzer import SecurityAnalyzer


def main():

    print("=" * 70)
    print(f"{APPLICATION_NAME} Security Operations Platform")
    print(f"Version: {APPLICATION_VERSION}")
    print("=" * 70)

    parser = LogParser()
    detector = DetectionEngine()
    analyzer = SecurityAnalyzer()

    print("\n[1] Reading Linux logs...")

    parsed_logs = parser.parse()

    print(f"[+] Parsed events: {len(parsed_logs)}")

    print("\n[2] Running detection rules...")

    alerts = detector.detect(parsed_logs)

    print(f"[+] Alerts generated: {len(alerts)}")

    print("\n[3] Running security analysis...")

    analyses = [
        analyzer.analyze(alert)
        for alert in alerts
    ]

    print(f"[+] Alerts analyzed: {len(analyses)}")

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

        print(f"Host: {alert['host']}")
        print(f"Service: {alert['service']}")
        print(f"Time: {alert['timestamp']}")
        print(f"Assessment: {analysis['assessment']}")
        print(f"Recommendation: {alert['recommendation']}")

    print("\n" + "=" * 70)

    # Temporary machine-readable output.
    # The API/database will consume this later.
    with open(
        "aisop_output.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            analyses,
            file,
            indent=4,
        )

    print("JSON output written to aisop_output.json")


if __name__ == "__main__":
    main()