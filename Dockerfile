# Образ стенда cps-update-lab: один образ для всех служб (подготовка, сервер обновлений, контроллер,
# HMI, инструменты).
#
# Версии закреплены: базовые образы — по дайджесту; cosign — по SHA-256 из cosign_checksums.txt
# выпуска v2.4.1; scii-agent (scii-verify), scii-gate и source-match — по коммиту; зависимости
# Python — по хешам колёс (docker/requirements.lock). Пакеты Debian (git, gnupg) берутся из
# зеркала базового образа.
#
# За корпоративным прокси с собственным УЦ передайте его сертификат секретом сборки:
#   docker build --secret id=ca,src=/путь/к/ca.pem -t cps-update-lab .

ARG RUST_IMAGE=rust:1.97.0-slim-trixie@sha256:686a437ead83701e8f871e66e838c3ec55f46b5fc235b025756396ac823bdc51
ARG PYTHON_IMAGE=python:3.12-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
ARG TARGETARCH

# ---- агент проверки квитанции на устройстве ----
FROM ${RUST_IMAGE} AS agent
ARG SCII_VERIFY_REV=1c4ac0ffbc5278c493db8a3ed8eae5cf8eef85e3
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/ca; fi; \
    cargo install --locked --root /out --git https://github.com/alexqzm/scii-verify --rev "${SCII_VERIFY_REV}" scii-agent

# ---- cosign: двоичный файл выпуска, проверка по SHA-256 ----
FROM scratch AS cosign-amd64
ADD --checksum=sha256:8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b --chmod=0755 \
    https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64 /cosign

FROM scratch AS cosign-arm64
ADD --checksum=sha256:3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a --chmod=0755 \
    https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-arm64 /cosign

FROM cosign-${TARGETARCH} AS cosign

# ---- стенд ----
FROM ${PYTHON_IMAGE}
ARG SCII_GATE_REV=d210811f27a9b9302f018faf7f019d38dfbb9227
ARG SOURCE_MATCH_REV=939ab5f07902ebaf78a3163a2f9277dedd375475

RUN apt-get update \
 && apt-get install -y --no-install-recommends git gnupg \
 && rm -rf /var/lib/apt/lists/*

COPY docker/requirements.lock /tmp/requirements.lock
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca GIT_SSL_CAINFO=/run/secrets/ca; fi; \
    pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore --require-hashes --only-binary=:all: \
        -r /tmp/requirements.lock \
 && pin() { git clone -q "https://github.com/alexqzm/$1" "/opt/$1" \
      && git -C "/opt/$1" -c advice.detachedHead=false checkout -q "$2" \
      && test "$(git -C "/opt/$1" rev-parse HEAD)" = "$2" \
      && rm -rf "/opt/$1/.git"; } \
 && pin scii-gate "${SCII_GATE_REV}" \
 && pin source-match "${SOURCE_MATCH_REV}" \
 && rm /tmp/requirements.lock

COPY --from=agent /out/bin/scii-agent /usr/local/bin/scii-agent
COPY --from=cosign /cosign /usr/local/bin/cosign
COPY cpslab /opt/cpslab/cpslab
COPY --chmod=0755 docker/cpslab docker/source-match /usr/local/bin/

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin lab \
 && mkdir /lab && chown lab:lab /lab

ENV PYTHONPATH=/opt/cpslab:/opt/scii-gate:/opt/source-match \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CPSLAB_HOME=/lab

USER lab
WORKDIR /lab
ENTRYPOINT ["cpslab"]
CMD ["doctor"]
