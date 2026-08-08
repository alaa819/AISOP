from app.models.alert import Alert


class SecurityAnalyzer:
    """
    Produces a human-readable security assessment.

    This layer is intentionally separated from the detection engine
    so that a real LLM can be integrated later without changing
    detection logic.
    """

    def analyze(self, alert: Alert) -> dict:

        if alert.severity == "CRITICAL":
            priority = "Immediate investigation required."

        elif alert.severity == "HIGH":
            priority = "High-priority investigation recommended."

        elif alert.severity == "MEDIUM":
            priority = "Investigation recommended."

        else:
            priority = "Monitor and verify activity."

        return {
            "alert": alert.to_dict(),
            "assessment": priority,
            "analyst_summary": (
                f"{alert.title} detected on {alert.host}. "
                f"Current risk score: {alert.risk_score}/100."
            ),
        }