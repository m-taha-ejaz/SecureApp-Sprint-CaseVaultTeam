FROM python:3.12-slim AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY native/ native/
COPY scripts/build_native.sh scripts/build_native.sh
RUN sh scripts/build_native.sh

FROM python:3.12-slim AS app
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir 'gunicorn>=23,<25' \
    && groupadd --gid 10001 appuser && useradd -M --uid 10001 --gid 10001 appuser
COPY secureapp/ secureapp/
COPY --from=builder /src/bin/safe_filename bin/safe_filename
RUN mkdir -p instance/uploads && chown -R appuser:appuser /app/instance
USER appuser
EXPOSE 8000
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "secureapp.main:create_app()", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-"]

FROM python:3.12-slim AS lab
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
RUN sh scripts/build_native.sh
CMD ["bash"]
