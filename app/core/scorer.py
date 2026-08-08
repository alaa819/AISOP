from app.config.settings import (
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
)


class RiskScorer:
    """
    Converts detection information into a normalized risk score.
    """

    @staticmethod
    def calculate(base_score: int, occurrence_count: int = 1) -> int:

        score = base_score

        # Repeated events increase risk.
        if occurrence_count >= 3:
            score += 15

        if occurrence_count >= 5:
            score += 15

        return min(score, 100)

    @staticmethod
    def severity(score: int) -> str:

        if score >= RISK_CRITICAL:
            return "CRITICAL"

        if score >= RISK_HIGH:
            return "HIGH"

        if score >= RISK_MEDIUM:
            return "MEDIUM"

        return "LOW"