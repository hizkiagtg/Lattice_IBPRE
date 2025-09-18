print("Main module loaded.")
import time
import sys
import random
import string
from .sibpre import SIBPRE

def tune_lattice_parameters(num_trials=5):
    """
    Tests various parameters for the SIBPRE scheme and reports performance.
    """
    param_configs = [
        {'n': 8, 'q': 8191, 'sigma': 0.3},
        {'n': 8, 'q': 8191, 'sigma': 0.5},
        {'n': 12, 'q': 16381, 'sigma': 0.3},
        {'n': 12, 'q': 16381, 'sigma': 0.5},
        {'n': 16, 'q': 32771, 'sigma': 0.3},
        {'n': 16, 'q': 32771, 'sigma': 0.5},
    ]

    results = {}
    id_delegator = "alice@example.com"
    id_delegatee = "bob@example.com"
    chars = string.ascii_lowercase + string.digits

    for config in param_configs:
        n, q, sigma = config['n'], config['q'], config['sigma']
        print(f"\n--- Tuning for n={n}, q={q}, sigma={sigma} ---")

        times = {'rkgen': [], 'encrypt': [], 'reencrypt': [], 'decrypt': [], 'redecrypt': []}
        sizes = {'rekey': [], 'ciphertext': [], 'reencrypted': []}
        failures = {'decrypt': 0, 'redecrypt': 0, 'skipped': 0}
        
        # 1. Setup (once per configuration)
        start_time = time.time()
        sibpre = SIBPRE(n=n, q=q, sigma=sigma)
        setup_time = time.time() - start_time
        A, u = sibpre.PP
        pk_size = sys.getsizeof(A) + sys.getsizeof(u)
        
        # 2. Key Extraction (once per configuration)
        start_time = time.time()
        sk_alice = sibpre.Extract(id_delegator)
        sk_bob = sibpre.Extract(id_delegatee)
        extract_time = time.time() - start_time
        sk_size = sys.getsizeof(sk_alice)

        # 3. Re-encryption Key Generation (once per configuration)
        start_time = time.time()
        rk = sibpre.ReKeyGen(sk_alice, id_delegator, id_delegatee)
        times['rkgen'].append(time.time() - start_time)
        sizes['rekey'].append(sys.getsizeof(rk))

        for trial in range(num_trials):
            msg = ''.join(random.choice(chars) for _ in range(2))
            
            try:
                # 4. Encrypt
                start_time = time.time()
                ciphertext = sibpre.Enc(id_delegator, msg)
                times['encrypt'].append(time.time() - start_time)
                sizes['ciphertext'].append(sys.getsizeof(ciphertext['key_ct']) + sys.getsizeof(ciphertext['enc_msg']))

                # 5. Decrypt Original
                start_time = time.time()
                decrypted_msg = sibpre.Dec(sk_alice, ciphertext)
                times['decrypt'].append(time.time() - start_time)
                if decrypted_msg != msg:
                    failures['decrypt'] += 1

                # 6. Re-Encrypt
                start_time = time.time()
                re_encrypted = sibpre.ReEnc(rk, ciphertext)
                times['reencrypt'].append(time.time() - start_time)
                sizes['reencrypted'].append(sys.getsizeof(re_encrypted['key_ct']) + sys.getsizeof(re_encrypted['enc_msg']))

                # 7. Decrypt Re-Encrypted
                start_time = time.time()
                redecrypted_msg = sibpre.Dec(sk_bob, re_encrypted)
                times['redecrypt'].append(time.time() - start_time)
                if redecrypted_msg != msg:
                    failures['redecrypt'] += 1

            except Exception as e:
                print(f"  Trial {trial+1} failed with error: {e}")
                failures['skipped'] += 1

        # Calculate and store average results
        avg_times = {k: (sum(v) / len(v)) if v else 0 for k, v in times.items()}
        avg_sizes = {k: (sum(v) / len(v)) if v else 0 for k, v in sizes.items()}

        results[f"n{n}_q{q}_s{sigma}"] = {
            'times': {'setup': setup_time, 'extract': extract_time, **avg_times},
            'sizes': {'public_key': pk_size, 'private_key': sk_size, **avg_sizes},
            'failures': failures
        }
        
        # Print summary for the current configuration
        print(f"  Setup Time: {setup_time:.4f}s | Extract Time: {extract_time:.4f}s")
        print(f"  Avg Encrypt: {avg_times['encrypt']:.4f}s | Avg Decrypt: {avg_times['decrypt']:.4f}s")
        print(f"  Avg ReKeyGen: {avg_times['rkgen']:.4f}s | Avg ReEncrypt: {avg_times['reencrypt']:.4f}s | Avg ReDecrypt: {avg_times['redecrypt']:.4f}s")
        print(f"  Avg Ciphertext Size: {avg_sizes['ciphertext'] / 1024:.2f} KB")
        print(f"  Failures: Decrypt {failures['decrypt']}, Re-Decrypt {failures['redecrypt']}, Skipped {failures['skipped']}")

    return results

if __name__ == "__main__":
    print("Starting SIBPRE testing...")
    tune_lattice_parameters(num_trials=10)
    print("\n--- Testing Complete ---")