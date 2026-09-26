# Failover LB
#
# Two stages: the builder compiles wheels for the packages with C code
# (argon2-cffi, cryptography, httptools), so the runtime image has no
# compiler in it.
#
# The image runs as a normal user.  Anything that needs root goes through the
# host agent over a bind-mounted socket; host-agent/ has the short list of
# what it will do.  That list is the real security boundary.

# ==============================================================================
# Stage 1, build the wheels
# ==============================================================================
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wheels
COPY requirements.txt .
RUN pip wheel --wheel-dir=/wheels -r requirements.txt


# ==============================================================================
# Stage 2, the image we actually run
# ==============================================================================
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="Failover LB" \
      org.opencontainers.image.description="Clustered web GUI, health checked backend pools, and Lets Encrypt automation for nginx built from source" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    NFM_DATA_DIR=/data \
    NFM_AGENT_SOCKET=/run/nginxmgr/agent.sock

# curl is for the health check (and for poking around during an outage).
# tini reaps zombies from the short-lived children the health checker and
# certbot hooks spawn.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Pinned uid/gid so the agent socket and data volume have predictable
# ownership.  install.sh creates a matching nginxmgr group on the host and
# gives it the socket, which is how this non-root user can open it.
ARG NFM_UID=10001
ARG NFM_GID=10001
RUN groupadd --gid "${NFM_GID}" nginxmgr \
    && useradd --uid "${NFM_UID}" --gid "${NFM_GID}" \
        --home-dir /app --no-create-home --shell /usr/sbin/nologin nginxmgr

COPY --from=builder /wheels /wheels
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-index --find-links=/wheels -r /tmp/requirements.txt \
    && rm -rf /wheels /tmp/requirements.txt

WORKDIR /app
COPY app/ /app/app/

# Fail the build on undefined names.  A missing import only blows up when
# that line runs, which can be a 500 on some rarely used button.
RUN pip install --no-cache-dir pyflakes==3.2.0 \
    && if python -m pyflakes app/ | grep -i "undefined name"; then \
           echo "BUILD STOPPED: the names above are used but never imported."; \
           exit 1; \
       fi \
    && pip uninstall -y pyflakes >/dev/null 2>&1 || true

# /data holds the database, the cluster CA, and this node's own key pair.  It
# is a volume so pulling a new image never wipes out the cluster trust.
RUN mkdir -p /data && chown -R nginxmgr:nginxmgr /data /app
VOLUME ["/data"]

USER nginxmgr

EXPOSE 7443

# Liveness, not /readyz.  A healthy standby is not ready but should not be
# restarted for it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsk https://127.0.0.1:7443/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "app.main"]
