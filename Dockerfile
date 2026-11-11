FROM python:3.14-slim

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system aegis \
    && useradd --system --gid aegis --home-dir /app aegis \
    && mkdir -p /app/backend /data/audit_checkpoints \
    && chown -R aegis:aegis /app /data \
    && chmod 700 /data/audit_checkpoints

WORKDIR /app/backend

COPY --chown=aegis:aegis backend/requirements.lock ./requirements.lock

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.lock \
    && rm -rf /usr/local/lib/python3.14/site-packages/setuptools* \
              /usr/local/lib/python3.14/site-packages/_distutils_hack \
              /usr/local/lib/python3.14/site-packages/distutils-precedence.pth \
    && test -z "$(find /usr/local/lib/python3.14/site-packages -maxdepth 1 -name 'setuptools*' -print -quit)"

COPY --chown=aegis:aegis backend/ .

USER aegis

EXPOSE 8000

CMD ["sh", "-c", "umask 077 && checkpoint_dir=\"${AEGIS_AUDIT_CHECKPOINT_DIR:-/data/audit_checkpoints}\" && database_path=\"${AEGIS_DATABASE_PATH:-/data/aegis.db}\" && mkdir -p \"$checkpoint_dir\" && chmod 700 \"$checkpoint_dir\" && if [ -f \"$database_path\" ]; then chmod 600 \"$database_path\"; fi && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
