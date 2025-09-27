## Build the Docker Image

From the repository root (where the `Dockerfile` lives):

```
docker build -t sibpre-app .
```

On Apple Silicon (arm64) add `--platform linux/amd64` to avoid Docker’s platform warning.

The resulting image bundles SageMath, PyCryptodome, and pytest so the lattice IB-PRE
experiments and unit tests can run consistently.

---

## Run the Experimental Harness (Chapter 3 Methodology)

The container’s default command executes `Lattice_IBPRE/src/main.py`, which implements
the workflow described in Bab 3:

```
docker run --rm sibpre-app
```

On arm64 hosts supply `--platform linux/amd64` as needed.

Any CLI options accepted by the harness can be appended. For example, to focus on the
message-size study with custom payload lengths and fewer trials:

```
docker run --rm sibpre-app --experiment message --trials 5 --message-bits 16 32 64
```

Running the harness directly from a local Sage environment uses the Sage Python
interpreter:

```
sage -python -m Lattice_IBPRE.src.main --experiment all --trials 10 --output results.json
```

The `--output` flag stores raw timing and size metrics for later analysis.

---

## Run the Test Suite

Execute the unit tests inside Docker (override the entrypoint to run pytest):

```
docker run --rm --entrypoint sage sibpre-app -python -m pytest tests
```

Again, add `--platform linux/amd64` on Apple Silicon if required.

Or invoke them locally (requires SageMath plus PyCryptodome/pytest installed):

```
sage -python -m pytest tests
```

The tests cover the MP12 trapdoor routines, FRD encoder, hybrid AES helpers, and
end-to-end SIBPRE flows over multiple message sizes.
