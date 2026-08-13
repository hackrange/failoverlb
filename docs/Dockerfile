FROM python:3.12-slim-bookworm

# chromium comes from the distribution rather than from playwright's own
# download, because playwright's browser build refuses to run as root without
# a sandbox flag and the distribution one is already patched by apt.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium fonts-dejavu-core fonts-liberation ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# python-docx writes the manual, pillow annotates the screenshots, and
# playwright drives a real browser through the GUI so the pictures in the
# manual are of the thing working rather than mock ups of it.
RUN pip install --no-cache-dir \
      python-docx==1.1.2 \
      pillow==11.0.0 \
      playwright==1.49.0

# Point playwright at the chromium that apt installed.  Without this it looks
# for its own copy under ~/.cache and fails with a message about running
# "playwright install", which would pull a second browser we do not need.
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/lib/chromium
ENV NFM_CHROMIUM=/usr/bin/chromium

WORKDIR /docs
