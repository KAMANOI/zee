# OSS Scanner build for Zee (https://github.com/KAMANOI/zee).
# Contract: the checkout is the build context; it lives at /src in the image.
# The network is available only while this file builds. Everything the tests
# need (including the optional MCP extra) is installed here.
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git python3 python3-venv python3-pip \
    && apt-get clean && find /var/lib/apt/lists -type f -delete

COPY . /src
WORKDIR /src

# Zee itself has no runtime dependency; "test" adds pytest, "mcp" adds the
# optional MCP server layer (zee.mcp.*), which is in scope.
RUN python3 -m venv /opt/venv \
    && pip install -e ".[test,mcp]"

# Smoke-run the suite so the image is known to work, but do not let a failing
# test abort the build. Re-run it offline with: cd /src && pytest tests/ -q
RUN cd /src && (pytest tests/ -q -p no:cacheprovider || echo "WARNING: pytest reported failures")
