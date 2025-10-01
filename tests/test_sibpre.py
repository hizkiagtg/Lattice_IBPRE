import pytest
from sage.all import set_random_seed
import string

from Lattice_IBPRE.src.sibpre import SIBPRE


@pytest.fixture(autouse=True)
def _seed():
    set_random_seed(4242)


def _build_scheme():
    return SIBPRE(n=4, q=12289, sigma=1.1)


def test_extract_solution():
    scheme = _build_scheme()
    u = scheme.PP[1]
    A_id, _ = scheme.matrix_for_identity("alice@example.com")
    sk = scheme.Extract("alice@example.com")
    assert (A_id * sk) % scheme.q == u


def test_sampleo_matches_extract_equation():
    scheme = _build_scheme()
    u = scheme.PP[1]
    x_mod, _ = scheme.SampleO("alice@example.com", u)
    A_id, _ = scheme.matrix_for_identity("alice@example.com")
    assert (A_id * x_mod) % scheme.q == u


def test_encrypt_decrypt_roundtrip():
    scheme = _build_scheme()
    identity = "alice@example.com"
    plaintext = "hi"
    ciphertext = scheme.Enc(identity, plaintext)
    sk = scheme.Extract(identity)
    decrypted = scheme.Dec(sk, ciphertext)
    assert decrypted == plaintext


def test_reencrypt_and_decrypt():
    scheme = _build_scheme()
    delegator = "alice@example.com"
    delegatee = "bob@example.com"
    message = "ok"

    ct = scheme.Enc(delegator, message)
    sk_i = scheme.Extract(delegator)
    sk_j = scheme.Extract(delegatee)
    rekey = scheme.ReKeyGen(sk_i, delegator, delegatee)
    new_ct = scheme.ReEnc(rekey, ct)

    assert scheme.Dec(sk_i, ct) == message
    assert scheme.Dec(sk_j, new_ct) == message


def test_frd_full_rank_difference():
    scheme = _build_scheme()
    H_alice = scheme.FRD("alice@example.com")
    H_bob = scheme.FRD("bob@example.com")
    diff = (H_alice - H_bob) % scheme.q
    assert diff.rank() == scheme.n


def test_aes_helper_supports_multiple_lengths():
    scheme = _build_scheme()
    for byte_len in [2, 4, 8, 16, 32]:
        payload = bytes((i % 256 for i in range(byte_len)))
        key, nonce, ct, tag = scheme.aes_encrypt(payload)
        recovered = scheme.aes_decrypt(key, nonce, ct, tag)
        assert recovered == payload


def test_encrypt_handles_various_message_sizes():
    scheme = _build_scheme()
    alphabet = string.ascii_lowercase
    identity = "alice@example.com"
    for byte_len in [2, 4, 8, 16, 32]:
        plaintext = ''.join(alphabet[i % len(alphabet)] for i in range(byte_len))
        ciphertext = scheme.Enc(identity, plaintext)
        sk = scheme.Extract(identity)
        assert scheme.Dec(sk, ciphertext) == plaintext
