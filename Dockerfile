# Use the official SageMath image as the base (modern, non-EOL)
FROM sagemath/sagemath:10.4

# Always flush Python stdout/stderr
ENV PYTHONUNBUFFERED=1

USER root
WORKDIR /usr/src

# Fix EOL Ubuntu repositories + install git
RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# ──────────────────────────────────────────────────────────────
# CRITICAL FIX: install the CURRENT lattice-estimator correctly
# ──────────────────────────────────────────────────────────────
RUN rm -rf /opt/lattice-estimator && \
    git clone --depth 1 https://github.com/malb/lattice-estimator.git /opt/lattice-estimator && \
    sage -pip install --no-cache-dir -e /opt/lattice-estimator
#                                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#          this does "pip install -e ." inside the repo → registers the new API

# Install other Python dependencies
RUN sage -pip install --no-cache-dir pycryptodome pytest

# Copy your code
COPY . ./Lattice_IBPRE
WORKDIR /usr/src/Lattice_IBPRE

# Make Python find your code + the estimator
ENV PYTHONPATH=/usr/src:/opt/lattice-estimator

USER sage

# Optional debug
RUN python -c "from estimator import LWE; print('Estimator version works:', LWE)"

ENTRYPOINT ["sage", "-python", "-u", "-m", "Lattice_IBPRE.src.main"]
CMD []
