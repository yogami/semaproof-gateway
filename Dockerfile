FROM python:3.11-slim

WORKDIR /app

# Hardened environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user for security
RUN groupadd -r semaproof && useradd -r -g semaproof semaproof
RUN mkdir -p /app/compliance_logs && chown -R semaproof:semaproof /app

COPY . /app
RUN chown -R semaproof:semaproof /app

USER semaproof

EXPOSE $PORT

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
