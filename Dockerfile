# Failover LB
#
# Two stages here.  The builder compiles the wheels, since a few of these
# packages have C code in them (argon2-cffi, cryptography, httptools).  Doing
# it this way means the image we actually run has no compiler in it, which is
# what you want on a production load balancer.
#
# The image runs as a normal user, not root.  It never touches the host on its
# own.  Anything that needs root goes through the host agent over a socket we
# bind mount in.  Look at host-agent/ for the short list of things that agent
# will agree to do.  That list is the real security line here, not the
# container.

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

# curl is in here for the container health check, and so you have something to
# poke around with when you shell in during an outage.  tini cleans up zombie
# processes, which matters because the health checker and the certbot hooks
# both spawn short lived children.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# We pin the uid and gid so the socket we bind mount and the data volume have
# ownership we can count on.  install.sh makes a matching nginxmgr group on the
# host and gives the socket to that group.  That is how a non root process in
# here is allowed to open it.
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

# Catch names that are used but never imported, at build time.
#
# A missing import does not show up when the module loads.  Python only looks
# the name up when that line actually runs, so it sits there quietly until
# somebody clicks the one button that reaches it and gets a 500.  That is
# exactly how a NodeRole that was never imported shipped and broke removing a
# node.  pyflakes finds these in a second, so the build fails instead of the
# user.
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

# This hits the plain liveness endpoint, not /readyz.  A node sitting there as
# a healthy standby is alive and doing its job.  We do not want docker
# restarting it just because it is not the active one right now.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsk https://127.0.0.1:7443/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "app.main"]
