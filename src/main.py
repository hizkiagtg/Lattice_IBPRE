"""Experimental harness for the lattice-based SIBPRE scheme.

The script follows the research methodology described in Chapter 3 by
providing:

1. Message-size experiments (Section 3.4.1) covering payloads of
   16, 32, 64, 128, and 256 bits via AES-GCM hybrid encryption.
2. Parameter-variation experiments (Section 3.4.2) across tunable
   lattice parameters (n, q, sigma).

Usage:
    python -m Lattice_IBPRE.src.main --experiment message --trials 5
    python -m Lattice_IBPRE.src.main --experiment params
    python -m Lattice_IBPRE.src.main --experiment all --output results.json

The script prints summaries to stdout and optionally stores raw metrics
in JSON for downstream analysis (Section 3.6).
"""

import argparse
import itertools
import json
import pickle
import random
import statistics
import string
import time
from collections import defaultdict

from .sibpre import SIBPRE

# ---------------------------------------------------------------------------
# Message generation helpers (Section 3.3.2, hybrid AES-GCM payloads)
# ---------------------------------------------------------------------------
ASCII_ALPHABET = string.ascii_letters + string.digits


def generate_random_message(bit_length, rng=None):
    if bit_length % 8 != 0:
        raise ValueError("bit_length must be divisible by 8")
    if rng is None:
        rng = random
    byte_length = bit_length // 8
    return ''.join(rng.choice(ASCII_ALPHABET) for _ in range(byte_length))


def sizeof(obj):
    return len(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))


def time_call(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return elapsed, result


# ---------------------------------------------------------------------------
# Experiment 1: Message-size overhead (Section 3.4.1)
# ---------------------------------------------------------------------------

def run_message_size_experiment(message_bits, trials, scheme_params, rng=None):
    if rng is None:
        rng = random

    results = {
        'parameters': {
            'n': scheme_params['n'],
            'q': scheme_params['q'],
            'sigma': scheme_params['sigma'],
        },
        'message_bits': message_bits,
        'trials': trials,
        'timings': defaultdict(list),
        'sizes': defaultdict(list),
    }

    setup_time, scheme = time_call(
        SIBPRE,
        n=scheme_params['n'],
        q=scheme_params['q'],
        sigma=scheme_params['sigma'],
    )
    results['timings']['setup'].append(setup_time)

    identities = {
        'delegator': 'alice@example.com',
        'delegatee': 'bob@example.com',
    }

    t_extract, sk_delegator = time_call(scheme.Extract, identities['delegator'])
    results['timings']['extract'].append(t_extract)
    t_extract_bob, sk_delegatee = time_call(scheme.Extract, identities['delegatee'])
    results['timings']['extract'].append(t_extract_bob)

    t_rk, rekey = time_call(
        scheme.ReKeyGen,
        sk_delegator,
        identities['delegator'],
        identities['delegatee'],
    )
    results['timings']['rkgen'].append(t_rk)
    results['sizes']['secret_key'].append(sizeof(sk_delegator))
    results['sizes']['rekey'].append(sizeof(rekey))

    for _ in range(trials):
        message = generate_random_message(message_bits, rng=rng)

        t_enc, ciphertext = time_call(scheme.Enc, identities['delegator'], message)
        results['timings']['encrypt'].append(t_enc)
        results['sizes']['ciphertext'].append(sizeof(ciphertext))

        t_dec, recovered = time_call(scheme.Dec, sk_delegator, ciphertext)
        results['timings']['decrypt'].append(t_dec)
        results['correct_decrypt'] = True if recovered == message else False

        t_reenc, reenc_ct = time_call(scheme.ReEnc, rekey, ciphertext)
        results['timings']['reencrypt'].append(t_reenc)
        results['sizes']['reencrypted'].append(sizeof(reenc_ct))

        t_redec, redec_message = time_call(scheme.Dec, sk_delegatee, reenc_ct)
        results['timings']['redecrypt'].append(t_redec)
        results['correct_redecrypt'] = True if redec_message == message else False

    results['timings'] = {k: list(v) for k, v in results['timings'].items()}
    results['sizes'] = {k: list(v) for k, v in results['sizes'].items()}
    return results


def summarise_message_experiments(records):
    summary = []
    for record in records:
        row = {
            'message_bits': record['message_bits'],
            'n': record['parameters']['n'],
            'q': record['parameters']['q'],
            'sigma': record['parameters']['sigma'],
            'ciphertext_bytes_avg': statistics.mean(record['sizes']['ciphertext']) if record['sizes']['ciphertext'] else 0,
            'reencrypted_bytes_avg': statistics.mean(record['sizes']['reencrypted']) if record['sizes']['reencrypted'] else 0,
            'encrypt_ms_avg': statistics.mean(record['timings']['encrypt']) * 1000,
            'decrypt_ms_avg': statistics.mean(record['timings']['decrypt']) * 1000,
            'reedec_ms_avg': statistics.mean(record['timings']['redecrypt']) * 1000,
        }
        summary.append(row)
    return summary


# ---------------------------------------------------------------------------
# Experiment 2: Parameter variation (Section 3.4.2)
# ---------------------------------------------------------------------------

def run_parameter_variation(grid, message_bits, trials, rng=None):
    if rng is None:
        rng = random

    records = []
    for n, q, sigma in itertools.product(grid['n'], grid['q'], grid['sigma']):
        params = {'n': n, 'q': q, 'sigma': sigma}
        try:
            record = run_message_size_experiment(
                message_bits=message_bits,
                trials=trials,
                scheme_params=params,
                rng=rng,
            )
            record['status'] = 'success'
        except Exception as exc:  # noqa: BLE001 - we need to log all failures
            record = {
                'parameters': params,
                'message_bits': message_bits,
                'trials': 0,
                'timings': {},
                'sizes': {},
                'status': 'failed',
                'error': str(exc),
            }
        records.append(record)
    return records


def summarise_parameter_variation(records):
    summary = []
    for record in records:
        entry = {
            'n': record['parameters']['n'],
            'q': record['parameters']['q'],
            'sigma': record['parameters']['sigma'],
            'status': record.get('status', 'unknown'),
        }
        if record.get('status') == 'success':
            encrypt_times = record['timings'].get('encrypt', [])
            if encrypt_times:
                entry['encrypt_ms_avg'] = statistics.mean(encrypt_times) * 1000
            ct_sizes = record['sizes'].get('ciphertext', [])
            if ct_sizes:
                entry['ciphertext_bytes_avg'] = statistics.mean(ct_sizes)
        else:
            entry['error'] = record.get('error')
        summary.append(entry)
    return summary


# ---------------------------------------------------------------------------
# CLI wiring (Section 3.1 workflow orchestration)
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="SIBPRE experimental harness")
    parser.add_argument(
        '--experiment',
        choices={'message', 'params', 'all'},
        default='all',
        help='Select which experiment to run',
    )
    parser.add_argument(
        '--trials',
        type=int,
        default=10,
        help='Number of trials per configuration',
    )
    parser.add_argument(
        '--message-bits',
        type=int,
        nargs='*',
        default=[16, 32, 64, 128, 256],
        help='Payload sizes (in bits) for the message experiment',
    )
    parser.add_argument(
        '--variation-message-bits',
        type=int,
        default=16,
        help='Payload size (in bits) for the parameter grid experiment',
    )
    parser.add_argument(
        '--n',
        type=int,
        nargs='*',
        default=[8, 12, 16],
        help='Candidate lattice dimensions for parameter variation',
    )
    parser.add_argument(
        '--q',
        type=int,
        nargs='*',
        default=[8191, 16381, 32771],
        help='Candidate moduli for parameter variation (prefer primes)',
    )
    parser.add_argument(
        '--sigma',
        type=float,
        nargs='*',
        default=[0.3, 0.5, 0.8],
        help='Candidate Gaussian widths for parameter variation',
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=None,
        help='Seed RNG for reproducible experiments',
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Optional path to store raw experiment results as JSON',
    )
    return parser.parse_args()


def main():
    args = parse_args()
    rng = random.Random(args.seed) if args.seed is not None else random
    raw_results = {}

    if args.experiment in {'message', 'all'}:
        message_records = []
        for bits in args.message_bits:
            params = {'n': 10, 'q': 65537, 'sigma': 0.5}
            record = run_message_size_experiment(
                message_bits=bits,
                trials=args.trials,
                scheme_params=params,
                rng=rng,
            )
            message_records.append(record)
        raw_results['message_experiment'] = message_records

        summary = summarise_message_experiments(message_records)
        print("\n=== Message Size Experiment (Section 3.4.1) ===")
        for row in summary:
            print(
                f"bits={row['message_bits']:>3} | encrypt={row['encrypt_ms_avg']:.3f} ms | "
                f"decrypt={row['decrypt_ms_avg']:.3f} ms | redecrypt={row['reedec_ms_avg']:.3f} ms | "
                f"CT≈{row['ciphertext_bytes_avg']:.1f} B | CT_re≈{row['reencrypted_bytes_avg']:.1f} B"
            )

    if args.experiment in {'params', 'all'}:
        grid = {'n': args.n, 'q': args.q, 'sigma': args.sigma}
        param_records = run_parameter_variation(
            grid=grid,
            message_bits=args.variation_message_bits,
            trials=args.trials,
            rng=rng,
        )
        raw_results['parameter_variation'] = param_records

        summary = summarise_parameter_variation(param_records)
        print("\n=== Parameter Variation Experiment (Section 3.4.2) ===")
        for entry in summary:
            if entry.get('status') == 'success':
                print(
                    f"n={entry['n']:>3}, q={entry['q']:>6}, sigma={entry['sigma']:.2f} | "
                    f"encrypt={entry['encrypt_ms_avg']:.3f} ms | CT≈{entry['ciphertext_bytes_avg']:.1f} B"
                )
            else:
                print(
                    f"n={entry['n']:>3}, q={entry['q']:>6}, sigma={entry['sigma']:.2f} | FAILED: {entry['error']}"
                )

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as handle:
            json.dump(raw_results, handle, indent=2)
        print(f"\nRaw results written to {args.output}")


if __name__ == '__main__':
    main()
