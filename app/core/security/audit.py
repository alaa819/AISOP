import logging


audit_logger = logging.getLogger("aisop.audit")


def log_audit_event(
    *,
    username: str,
    action: str,
    result: str,
    ip_address: str,
    endpoint: str,
) -> None:
    """
    Record a security-sensitive audit event.
    """

    audit_logger.info(
        "user=%s action=%s result=%s ip=%s endpoint=%s",
        username,
        action,
        result,
        ip_address,
        endpoint,
    )