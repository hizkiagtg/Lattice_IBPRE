"""
Quick helper to run the LWE estimator (Albrecht et al.) for given parameters.
Execute with Sage's Python: ``sage -python -m Lattice_IBPRE.src.lwe_estimator_runner``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from pprint import pprint
from typing import Any, Dict

def _ensure_estimator_on_path() -> None:
    """Best-effort: add lattice-estimator checkout to sys.path when missing."""
    env_hint = os.environ.get("LWE_ESTIMATOR_PATH") or "/opt/lattice-estimator"
    candidates = [
        env_hint,
        str(Path(__file__).resolve().parent.parent / "lattice-estimator"),
    ]
    for candidate in candidates:
        if candidate and candidate not in sys.path and (Path(candidate) / "estimator").exists():
            sys.path.append(candidate)


_ensure_estimator_on_path()

try:
    from estimator import LWE, ND
except ImportError as exc:  # pragma: no cover - guidance for manual runs
    raise SystemExit(
        "Missing dependency 'lwe-estimator' (lattice-estimator). Fetch it from:\n"
        "  https://github.com/malb/lattice-estimator\n"
        "and ensure that repository root is on PYTHONPATH, e.g.:\n"
        "  git clone https://github.com/malb/lattice-estimator /opt/lattice-estimator\n"
        "  export PYTHONPATH=$PYTHONPATH:/opt/lattice-estimator\n"
        "or set LWE_ESTIMATOR_PATH to the checkout directory."
    ) from exc

def _coerce(value: Any) -> Any:
    """Best-effort conversion so JSON dumping does not fail on Sage numbers."""
    for converter in (float, str):
        try:
            return converter(value)
        except Exception:
            continue
    return value


def _attack_to_dict(attack: Any) -> Dict[str, Any]:
    if isinstance(attack, dict):
        return {k: _coerce(v) for k, v in attack.items()}
    if hasattr(attack, "__dict__"):
        return {k: _coerce(v) for k, v in vars(attack).items()}
    return {"repr": repr(attack)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the LWE estimator for a (n, q, sigma) tuple."
    )
    parser.add_argument("--n", type=int, default=10, help="LWE dimension (default: 10)")
    parser.add_argument("--q", type=int, default=65537, help="modulus (default: 65537)")
    parser.add_argument(
        "--sigma",
        type=float,
        default=0.5,
        help="Gaussian stddev of the error distribution (default: 0.5)",
    )
    parser.add_argument(
        "--secret-distribution",
        choices=("unif", "ternary"),
        default="unif",
        help="Secret distribution passed to the estimator (default: unif).",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help="Number of LWE samples available to the attacker (default: n).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Dump a JSON-serialisable summary of the best attack.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    alpha = args.sigma / args.q
    if args.secret_distribution == "unif":
        secret = ND.UniformMod(args.q)
    else:
        weight = max(1, args.n // 3)
        secret = ND.SparseTernary(weight, weight, args.n)
    error = ND.DiscreteGaussian(args.sigma)
    samples = args.samples if args.samples is not None else args.n
    lwe_params = LWE.Parameters(
        n=args.n,
        q=args.q,
        Xs=secret,
        Xe=error,
        m=samples,
        tag=f"n={args.n}, q={args.q}, sigma={args.sigma}",
    )

    print(f"alpha = {alpha}")
    try:
        results = LWE.estimate.rough(lwe_params, quiet=False)
    except Exception as err:  # pragma: no cover - estimator is external
        print(f"[warn] Rough estimator failed: {err}")
        results = {}
    if not results:
        try:
            results = LWE.estimate(lwe_params, quiet=False)
        except Exception as err:  # pragma: no cover
            print(f"[warn] Full estimator failed: {err}")
            results = {}
    print("\nRaw estimator output (all attacks):")
    pprint(results)

    # Pick the attack with the smallest rop cost
    best_attack_name = None
    best_attack = None
    for name, attack in results.items():
        rop = attack.get("rop")
        if rop is None:
            continue
        if best_attack is None or rop < best_attack.get("rop", rop):
            best_attack = attack
            best_attack_name = name

    if best_attack:
        print(f"\nBest attack: {best_attack_name} (rop ≈ {best_attack.get('rop')})")

    if args.json:
        print("\nJSON summary:")
        summary = {
            "params": {
                "n": args.n,
                "q": args.q,
                "sigma": args.sigma,
                "alpha": alpha,
                "secret_distribution": args.secret_distribution,
                "samples": args.samples,
            },
            "attacks": {k: _attack_to_dict(v) for k, v in results.items()},
            "best_attack": {
                "name": best_attack_name,
                "data": _attack_to_dict(best_attack) if best_attack else None,
            },
        }
        print(json.dumps(summary, indent=2))

    if not results:
        print(
            "\n[notice] No attacks returned. This often happens for very small or ill-conditioned parameters; "
            "try larger n or different distributions."
        )


if __name__ == "__main__":
    main()
