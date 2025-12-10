# Use the official SageMath image as the base (modern, non-EOL)
FROM sagemath/sagemath:10.4

# Always flush Python stdout/stderr
ENV PYTHONUNBUFFERED=1

USER root
WORKDIR /usr/src

# Install git/CA certificates (Ubuntu Jammy in Sage 10.4 is still supported)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Pull the current lattice-estimator and install it (non-editable). Remove the top-level
# docker/ folder before install to avoid setuptools package-discovery errors.
RUN rm -rf /opt/lattice-estimator && \
    git clone --depth 1 https://github.com/malb/lattice-estimator.git /opt/lattice-estimator && \
    rm -rf /opt/lattice-estimator/docker && \
    sage -pip install --no-cache-dir --no-build-isolation /opt/lattice-estimator

# Install other Python dependencies
RUN sage -pip install --no-cache-dir pycryptodome pytest

# Copy your code
COPY . ./Lattice_IBPRE
WORKDIR /usr/src/Lattice_IBPRE

# Make Python find your code + the estimator
ENV PYTHONPATH=/usr/src:/opt/lattice-estimator

USER sage

ENTRYPOINT ["sage", "-python", "-u", "-m", "Lattice_IBPRE.src.main"]
CMD []
