import os

from dotenv import load_dotenv


load_dotenv()


JWT_SECRET_KEY = os.getenv("AISOP_JWT_SECRET")

if not JWT_SECRET_KEY:
    raise RuntimeError(
        "AISOP_JWT_SECRET is not configured."
    )


JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 30