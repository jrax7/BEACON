FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG DEBIAN_SNAPSHOT=20260824T000000Z

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN sed -i \
       -e "s|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|g" \
       -e "s|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|g" \
       /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' \
       > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
       fontconfig=2.15.0-2.3 \
       fonts-dejavu-core=2.37-8 \
       libharfbuzz-subset0=10.2.0-1+deb13u1 \
       libpango-1.0-0=1.56.3-1 \
       libpangoft2-1.0-0=1.56.3-1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system beacon \
    && useradd \
       --system \
       --gid beacon \
       --create-home \
       beacon


RUN mkdir -p /app/storage/reports \
    && chown -R beacon:beacon /app/storage

COPY requirements.txt requirements.lock build-requirements.lock install_dependencies.py /app/

RUN python -m pip install --require-hashes --requirement /app/build-requirements.lock \
    && python /app/install_dependencies.py \
    && rm /app/install_dependencies.py

COPY --chown=beacon:beacon app /app/app
COPY --chown=beacon:beacon alembic /app/alembic
COPY --chown=beacon:beacon alembic.ini /app/alembic.ini

ARG BEACON_VERSION=development
ARG BEACON_REVISION=unknown

LABEL org.opencontainers.image.title="BEACON Backend" \
      org.opencontainers.image.version="${BEACON_VERSION}" \
      org.opencontainers.image.revision="${BEACON_REVISION}"


USER beacon

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
