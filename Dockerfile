FROM python:3.14-slim

# Prevent Python from creating .pyc files
# and make logs appear immediately.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Application directory
WORKDIR /app

# Install Python dependencies first.
# This allows Docker to reuse the dependency layer
# when application code changes.
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy the AISOP application
COPY app ./app

# Create the database directory.
RUN mkdir -p /app/data

# Create a non-root user for the application.
RUN useradd \
    --create-home \
    --shell /usr/sbin/nologin \
    aisop

# Give the application user ownership of the
# application directory and database directory.
RUN chown -R aisop:aisop /app

# Run the application as a non-root user.
USER aisop

# AISOP API port
EXPOSE 8000

# Start FastAPI with Uvicorn.
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
