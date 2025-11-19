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

---

## Tune Lattice Parameters (Bab 6.4)

Section 6.4 of the thesis benchmarks lattice parameters by varying
`n ∈ {8, 12, 16}`, `q ∈ {8191, 16381, 32771}`, and `sigma ∈ {0.3, 0.5}` over 10
iterations on 8-bit messages. The harness now evaluates the full Cartesian
product of those sets (18 configurations) so that the impact of each parameter
can be isolated. Running the Docker image (or invoking `Lattice_IBPRE/src/main.py`
directly) executes both the payload-size study *and* the parameter-tuning
experiment, so one command collects everything:

```
docker run --rm sibpre-app
```

For direct programmatic use (without any CLI wrapper), import the helper
functions and call them from Python/Sage:

```
sage -python <<'PY'
from Lattice_IBPRE.src.main import run_parameter_tuning_suite, summarise_parameter_tuning

results = run_parameter_tuning_suite(method='empirical')
summarise_parameter_tuning(results)
PY
```

Empirical runs mirror the methodology from Bab 6.4 by re-running the sampler for
each tuple in the grid (they are slow for `n=16`). If you have freshly gathered
timing/size data from a new experiment, pass it via `timing_data`/`size_data` (or
`parameter_grid`) so the harness simply reports those measurements instead of
recomputing them live. The full 18-configuration sweep is computationally heavy;
adjust `iterations` or `parameter_grid` if you only need a subset while
prototyping.
