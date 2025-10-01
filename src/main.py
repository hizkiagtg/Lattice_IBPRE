import json
import pickle
import random
import statistics
import string
import time

from .sibpre import SIBPRE

ASCII_ALPHABET = string.ascii_letters + string.digits
DEFAULT_MESSAGE_BITS = [16] #, 32, 64, 128, 256]
DEFAULT_PARAMS = {'n': 8, 'q': 8191, 'sigma': 0.3}  

def print_table(headers, rows, title=""):
    if not rows:
        return
    widths = [max(len(str(item)) for item in col) for col in zip(headers, *rows)]
    if title:
        print(f"\n--- {title} ---")
    header_line = " | ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        print(" | ".join(f"{str(item):<{w}}" for item, w in zip(row, widths)))


def generate_random_message(bit_length, rng=None):
    """
    Generate a random ASCII message of given bit length.
    Ensures the message length is bit_length//8 bytes.
    """
    if bit_length % 8 != 0:
        raise ValueError("bit_length must be divisible by 8")
    if rng is None:
        rng = random
    byte_length = max(1, bit_length // 8)
    return ''.join(rng.choice(ASCII_ALPHABET) for _ in range(byte_length))


def sizeof(obj):
    return len(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))


def _ciphertext_size(ciphertext):
    return sizeof(ciphertext)


def run_message_size_suite(message_bits_list, trials, params, rng=None):
    if rng is None:
        rng = random

    setup_start = time.perf_counter()
    scheme = SIBPRE(n=params['n'], q=params['q'], sigma=params['sigma'])
    setup_time_ms = (time.perf_counter() - setup_start) * 1000
    delegator = "alice@example.com"
    delegatee = "bob@example.com"

    extract_start = time.perf_counter()
    sk_delegator = scheme.Extract(delegator)
    sk_delegatee = scheme.Extract(delegatee)
    keygen_time_ms = (time.perf_counter() - extract_start) * 1000

    rk_start = time.perf_counter()
    rekey = scheme.ReKeyGen(sk_delegator, delegator, delegatee)
    rekey_time_ms = (time.perf_counter() - rk_start) * 1000

    message_results = {}

    for bits in message_bits_list:
        timings = {'encrypt': [], 'decrypt': [], 'reencrypt': [], 'redecrypt': []}
        sizes = {'ciphertext': [], 'reencrypted': []}
        failures = {'decrypt': 0, 'redecrypt': 0}

        for _ in range(trials):
            message = generate_random_message(bits, rng=rng)

            # Encrypt
            start = time.perf_counter()
            ciphertext = scheme.Enc(delegator, message)
            timings['encrypt'].append(time.perf_counter() - start)
            sizes['ciphertext'].append(_ciphertext_size(ciphertext))

            # Decrypt (delegator)
            start = time.perf_counter()
            recovered = scheme.Dec(sk_delegator, ciphertext)
            timings['decrypt'].append(time.perf_counter() - start)
            if recovered != message:
                failures['decrypt'] += 1

            # ReEncrypt
            start = time.perf_counter()
            reenc = scheme.ReEnc(rekey, ciphertext)
            timings['reencrypt'].append(time.perf_counter() - start)
            sizes['reencrypted'].append(_ciphertext_size(reenc))

            # ReDecrypt (delegatee)
            start = time.perf_counter()
            redecrypted = scheme.Dec(sk_delegatee, reenc)
            timings['redecrypt'].append(time.perf_counter() - start)
            if redecrypted != message:
                failures['redecrypt'] += 1

        message_results[bits] = {
            'timings_ms': {name: statistics.mean(values) * 1000 for name, values in timings.items()},
            'sizes_bytes': {name: statistics.mean(values) for name, values in sizes.items()},
            'failures': failures,
        }

    return {
        'params': params,
        'num_trials': trials,
        'setup_time_ms': setup_time_ms,
        'keygen_time_ms': keygen_time_ms,
        'rekey_time_ms': rekey_time_ms,
        'message_results': message_results,
    }


def summarise(results):
    if not results:
        print("No data collected.")
        return

    params = results['params']
    print(
        f"\nRunning message-size experiment on lattice parameters "
        f"n={params['n']}, q={params['q']}, sigma={params['sigma']} "
        f"with {results['num_trials']} trials per payload..."
    )

    print(
        f"\nParameters: n={params['n']}, q={params['q']}, sigma={params['sigma']}"
    )
    print(
        f"Setup: {results['setup_time_ms']:.2f} ms | KeyGen: {results['keygen_time_ms']:.2f} ms | "
        f"ReKeyGen: {results['rekey_time_ms']:.2f} ms"
    )

    headers = [
        "Message bits",
        "Enc (ms)",
        "Dec (ms)",
        "ReEnc (ms)",
        "ReDec (ms)",
        "CT (bytes)",
        "ReCT (bytes)",
    ]
    rows = []
    for bits in sorted(results['message_results']):
        data = results['message_results'][bits]
        timings = data['timings_ms']
        sizes = data['sizes_bytes']
        rows.append([
            bits,
            f"{timings['encrypt']:.3f}",
            f"{timings['decrypt']:.3f}",
            f"{timings['reencrypt']:.3f}",
            f"{timings['redecrypt']:.3f}",
            f"{sizes['ciphertext']:.1f}",
            f"{sizes['reencrypted']:.1f}",
        ])

    print_table(headers, rows, "Message Size Experiment")


if __name__ == '__main__':
    rng = random.Random(42)
    params = DEFAULT_PARAMS
    results = run_message_size_suite(DEFAULT_MESSAGE_BITS, trials=5, params=params, rng=rng)
    summarise(results)
