"""Parameter tuning helpers aligned with the thesis experiments (Bab 6.4)."""

from __future__ import annotations

import pickle
import random
import statistics
import string
import time
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .sibpre import SIBPRE


ASCII_ALPHABET = string.ascii_letters + string.digits


def _random_message(bit_length: int, rng: random.Random) -> str:
    if bit_length % 8 != 0:
        raise ValueError("bit_length must be divisible by 8")
    byte_length = max(1, bit_length // 8)
    return ''.join(rng.choice(ASCII_ALPHABET) for _ in range(byte_length))


def _serialized_size(obj) -> int:
    return len(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))


THESIS_PARAMETER_GRID: Sequence[Dict[str, float]] = tuple(
    {"n": n, "q": q, "sigma": sigma}
    for n in (8, 12, 16)
    for q in (4093, 8191, 16381)
    for sigma in (0.3, 0.5)
)


TIMING_KEYS: Tuple[str, ...] = (
    "setup",
    "extract",
    "rekeygen",
    "encrypt",
    "reencrypt",
    "decrypt",
    "redecrypt",
)


@dataclass(frozen=True)
class ParameterResult:
    n: int
    q: int
    sigma: float
    timings: Dict[str, float]
    sizes: Dict[str, float]

    def as_dict(self) -> Dict[str, float]:
        return {
            "n": self.n,
            "q": self.q,
            "sigma": self.sigma,
            "timings": self.timings,
            "sizes": self.sizes,
        }


class ParameterTuner:
    """Collects raw timing and size metrics per lattice parameter tuple."""

    def __init__(
        self,
        method: str = "empirical",
        iterations: int = 5,
        message_bits: int = 8,
        seed: int = 1337,
        parameter_grid: Sequence[Dict[str, float]] | None = None,
        timing_data: Dict[Tuple[int, int, float], Dict[str, float]] | None = None,
        size_data: Dict[str, float] | None = None,
        verbose: bool = False,
    ) -> None:
        self.method = method
        self.iterations = iterations
        self.message_bits = message_bits
        self.seed = seed
        self.parameter_grid = parameter_grid or THESIS_PARAMETER_GRID
        self.timing_data = timing_data
        self.size_data = size_data or {}
        self.verbose = verbose
        self._results = self._load_results()
        if not self._results:
            raise ValueError(
                "Parameter tuning produced no results; supply timing data or use empirical mode."
            )

    def _load_results(self) -> List[ParameterResult]:
        if self.method == "thesis":
            if not self.timing_data:
                raise ValueError("No timing data supplied for thesis-based tuning.")
            results: List[ParameterResult] = []
            for cfg in self.parameter_grid:
                key = (int(cfg["n"]), int(cfg["q"]), float(cfg["sigma"]))
                if key not in self.timing_data:
                    raise ValueError(f"Missing timing data for parameter tuple {key}.")
                timings = self.timing_data[key]
                results.append(
                    ParameterResult(
                        n=key[0],
                        q=key[1],
                        sigma=key[2],
                        timings=timings,
                        sizes=dict(self.size_data),
                    )
                )
            return results
        if self.method == "empirical":
            return self._collect_empirical_results()
        raise ValueError(f"Unknown method '{self.method}'")

    def _collect_empirical_results(self) -> List[ParameterResult]:
        rng = random.Random(self.seed)
        delegator = "alice@example.com"
        delegatee = "bob@example.com"
        message = _random_message(self.message_bits, rng)
        results: List[ParameterResult] = []

        for cfg in self.parameter_grid:
            cfg_label = f"n={cfg['n']}, q={cfg['q']}, σ={cfg['sigma']}"
            if self.verbose:
                print(f"[param-tuning] starting {cfg_label}")
            config_start = time.perf_counter()
            timings: Dict[str, List[float]] = {key: [] for key in TIMING_KEYS}
            setup_start = time.perf_counter()
            scheme = SIBPRE(n=int(cfg["n"]), q=int(cfg["q"]), sigma=float(cfg["sigma"]))
            timings["setup"].append((time.perf_counter() - setup_start))

            extract_start = time.perf_counter()
            sk_delegator = scheme.Extract(delegator)
            timings["extract"].append(time.perf_counter() - extract_start)

            extract_start = time.perf_counter()
            sk_delegatee = scheme.Extract(delegatee)
            timings["extract"].append(time.perf_counter() - extract_start)

            rekey_start = time.perf_counter()
            rekey = scheme.ReKeyGen(sk_delegator, delegator, delegatee)
            timings["rekeygen"].append(time.perf_counter() - rekey_start)

            iteration_cipher_sizes: List[int] = []
            iteration_re_sizes: List[int] = []
            for _ in range(self.iterations):
                start = time.perf_counter()
                ciphertext = scheme.Enc(delegator, message)
                timings["encrypt"].append(time.perf_counter() - start)

                start = time.perf_counter()
                reenc = scheme.ReEnc(rekey, ciphertext)
                timings["reencrypt"].append(time.perf_counter() - start)

                start = time.perf_counter()
                _ = scheme.Dec(sk_delegator, ciphertext)
                timings["decrypt"].append(time.perf_counter() - start)

                start = time.perf_counter()
                _ = scheme.Dec(sk_delegatee, reenc)
                timings["redecrypt"].append(time.perf_counter() - start)

                iteration_cipher_sizes.append(_serialized_size(ciphertext))
                iteration_re_sizes.append(_serialized_size(reenc))

            averaged_timings = {
                key: statistics.mean(values)
                for key, values in timings.items()
                if values
            }
            sizes = {
                "pp_bytes": _serialized_size(scheme.PP),
                "sk_bytes": _serialized_size(sk_delegator),
                "rk_bytes": _serialized_size(rekey),
                "ciphertext_bytes": statistics.mean(iteration_cipher_sizes),
                "re_ciphertext_bytes": statistics.mean(iteration_re_sizes),
            }
            results.append(
                ParameterResult(
                    n=int(cfg["n"]),
                    q=int(cfg["q"]),
                    sigma=float(cfg["sigma"]),
                    timings=averaged_timings,
                    sizes=sizes,
                )
            )
            if self.verbose:
                elapsed = time.perf_counter() - config_start
                print(f"[param-tuning] finished {cfg_label} in {elapsed:.2f}s")
        return results

    def results(self) -> List[ParameterResult]:
        return list(self._results)

    def as_dicts(self) -> List[Dict[str, float]]:
        return [result.as_dict() for result in self._results]
