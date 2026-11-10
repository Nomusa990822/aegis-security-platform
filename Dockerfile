FROM python:3.14-slim

# Apply current Debian security updates before installing application packages.
RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system aegis \
    && useradd --system --gid aegis --home-dir /app aegis \
    && mkdir -p /app/backend /data/audit_checkpoints \
    && chown -R aegis:aegis /app /data

WORKDIR /app/backend

COPY --chown=aegis:aegis backend/requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.lock \
    && rm -rf /usr/local/lib/python3.14/site-packages/setuptools* \
        /usr/local/lib/python3.14/site-packages/_distutils_hack \
        /usr/local/lib/python3.14/site-packages/distutils-precedence.pth \
    && test -z "$(find /usr/local/lib/python3.14/site-packages -maxdepth 1 -name 'setuptools*' -print -quit)"

COPY --chown=aegis:aegis backend/ ./

USER aegis

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
