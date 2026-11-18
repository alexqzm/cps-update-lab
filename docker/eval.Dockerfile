# Образ эксперимента Э8 (experiments/agents/PROGRAM.md): стенд cps-update-lab и Claude Code для пакетных
# сеансов агента. Локальные модели работают в Ollama на хосте, образ обращается к ним по OLLAMA_HOST.
#
# Собирается поверх образа стенда: ./lab.sh eval-build (сначала собирает стенд, если его нет).
# Claude Code закреплён версией пакета npm, базовый образ Node — по дайджесту.

ARG NODE_IMAGE=node:22-trixie-slim@sha256:68c76cfad89921b927eae28ba21407475e29d0ce450afcdbe70c1532db042b64
ARG STAND_IMAGE=cps-update-lab:local

FROM ${NODE_IMAGE} AS claude
ARG CLAUDE_CODE_VERSION=2.1.327
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \
    npm install -g --no-audit --no-fund "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && cp "$(npm root -g)/@anthropic-ai/claude-code/bin/claude.exe" /claude \
 && /claude --version

FROM ${STAND_IMAGE}
COPY --from=claude /claude /usr/local/bin/claude
COPY cpslab /opt/cpslab/cpslab
USER root
RUN mkdir /runs && chown lab:lab /runs
USER lab
ENV CPSLAB_CLAUDE=/usr/local/bin/claude \
    DISABLE_AUTOUPDATER=1
