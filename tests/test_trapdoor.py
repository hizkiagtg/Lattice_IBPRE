import pytest
from sage.all import Zmod, vector, set_random_seed, block_matrix

from Lattice_IBPRE.src.utils import trap_gen, sample_preimage


@pytest.fixture(autouse=True)
def _seed():
    set_random_seed(12345)


def _matrix_equal(a, b):
    return all(a[i, j] == b[i, j] for i in range(a.nrows()) for j in range(a.ncols()))


def test_trap_gen_structure():
    n, q = 4, 12289
    info = trap_gen(n, q, m_bar=8 * n, k=5)
    A = info['A']
    A_bar = info['A_bar']
    R_mod = info['R_mod']
    G = info['G']

    expected_right = (A_bar * R_mod + G) % q
    actual_right = A[:, A_bar.ncols():]
    assert _matrix_equal(expected_right, actual_right)


def test_sample_preimage_solves_equation():
    n, q = 4, 12289
    info = trap_gen(n, q, m_bar=8 * n, k=5)
    Zq = Zmod(q)
    u = vector(Zq, [Zq.random_element() for _ in range(n)])
    sk_mod, _ = sample_preimage(
        info['A_bar'],
        info['R_int'],
        info['G'],
        u,
        q,
        sigma=4.0,
        R_mod=info['R_mod'],
    )
    right_block = (info['A_bar'] * info['R_mod'] + info['G']) % q
    A_full = info['A_bar'].augment(right_block)
    assert (A_full * sk_mod) % q == u
