RULES = [
    {
        "id": "AUTH-001",
        "name": "Failed SSH Authentication",
        "pattern": "Failed password",
        "base_score": 50,
        "severity": "MEDIUM",
        "description": (
            "A failed SSH authentication attempt was detected."
        ),
        "recommendation": (
            "Investigate the source address and determine whether "
            "multiple failed authentication attempts occurred."
        ),
    },

    {
        "id": "AUTH-002",
        "name": "Invalid SSH User",
        "pattern": "Invalid user",
        "base_score": 60,
        "severity": "MEDIUM",
        "description": (
            "An SSH authentication attempt targeted an invalid user."
        ),
        "recommendation": (
            "Investigate the source address for reconnaissance "
            "or brute-force activity."
        ),
    },

    {
        "id": "AUTH-003",
        "name": "Successful SSH Authentication",
        "pattern": "Accepted password",
        "base_score": 20,
        "severity": "LOW",
        "description": (
            "A successful SSH authentication event was detected."
        ),
        "recommendation": (
            "Verify that the authentication was expected."
        ),
    },

    {
        "id": "AUTH-004",
        "name": "Root SSH Authentication",
        "pattern": "Accepted password for root",
        "base_score": 90,
        "severity": "CRITICAL",
        "description": (
            "A successful SSH authentication to the root account "
            "was detected."
        ),
        "recommendation": (
            "Immediately verify whether this activity was authorized "
            "and investigate the source address."
        ),
    },
]