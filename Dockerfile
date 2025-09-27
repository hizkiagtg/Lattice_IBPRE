# Use the official SageMath image as the base
FROM sagemath/sagemath:9.5

# Always flush Python stdout/stderr
ENV PYTHONUNBUFFERED=1

# Set working directory and copy the project so Python can import Lattice_IBPRE
WORKDIR /usr/src

# Install dependencies required by the lattice scheme and its tests
RUN sage -pip install --no-cache-dir pycryptodome pytest

# Copy project sources required at runtime and for testing
COPY . ./Lattice_IBPRE

# Switch to project directory
WORKDIR /usr/src/Lattice_IBPRE

# Debug: verify that utils.py is copied and not empty
RUN echo "---- ls -l ./src ----" && ls -l ./src \
    && echo "---- utils.py size ----" && wc -c ./src/utils.py \
    && echo "---- utils.py head ----" && head -n 20 ./src/utils.py || true

# Make sure Python finds ./src
ENV PYTHONPATH=/usr/src

# Default entrypoint runs the experimental harness; extra CLI args are forwarded
ENTRYPOINT ["sage", "-python", "-u", "-m", "Lattice_IBPRE.src.main"]
CMD []
