# Use the official SageMath image as the base
FROM sagemath/sagemath:9.5

# Always flush Python stdout/stderr
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /usr/src/app

# Install dependencies
RUN sage -pip install --no-cache-dir pycryptodome

# Copy src into the image
COPY src ./src

# Debug: verify that utils.py is copied and not empty
RUN echo "---- ls -l ./src ----" && ls -l ./src \
    && echo "---- utils.py size ----" && wc -c ./src/utils.py \
    && echo "---- utils.py head ----" && head -n 20 ./src/utils.py || true

# Make sure Python finds ./src
ENV PYTHONPATH=/usr/src/app

# Default command
CMD ["sage", "-python", "-u", "-m", "src.main"]
