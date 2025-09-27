from sage.all import (
    Zmod,
    Matrix,
    vector,
    ZZ,
    ceil,
    log,
    block_matrix,
    Integer,
    random_matrix,
)
from sage.stats.distributions.discrete_gaussian_integer import (
    DiscreteGaussianDistributionIntegerSampler,
)


def generate_gadget_matrix(n, k, q):
    """Generate the n x (n*k) gadget matrix G with powers of two on the diagonal blocks."""  # noqa: E501
    Zq = Zmod(q)
    g_t = [2 ** j for j in range(k)]
    G = Matrix(Zq, n, n * k)
    for i in range(n):
        for j, value in enumerate(g_t):
            G[i, i * k + j] = Zq(value)
    return G


def lift_to_mod_q(vec, q):
    """Return a ZZ vector whose entries are the canonical representatives in [0, q)."""  # noqa: E501
    return vector(ZZ, [Integer(x) % q for x in vec])


def lift_to_signed(vec, q):
    """Return a ZZ vector with entries in (-(q//2), q//2]."""
    lifted = []
    for entry in vec:
        as_int = Integer(entry) % q
        if as_int > q // 2:
            as_int -= q
        lifted.append(as_int)
    return vector(ZZ, lifted)


def discrete_gaussian_vector(dimension, sigma):
    """Sample a ZZ vector from the discrete Gaussian with parameter sigma."""
    sampler = DiscreteGaussianDistributionIntegerSampler(sigma=sigma)
    return vector(ZZ, [Integer(sampler()) for _ in range(dimension)])


def gadget_decompose(vec, k, q):
    """Return the gadget decomposition of vec (assumed in Z_q^n) into base-2 digits."""  # noqa: E501
    digits = []
    for entry in vec:
        value = Integer(entry) % q
        for _ in range(k):
            digits.append(Integer(value & 1))
            value >>= 1
    return vector(ZZ, digits)


def gadget_recompose(digits, n, k, q):
    """Recompose gadget digits back into an n-dimensional vector over Z_q."""
    Zq = Zmod(q)
    output = []
    for i in range(n):
        acc = 0
        for j in range(k):
            acc += Integer(digits[i * k + j]) * (2 ** j)
        output.append(Zq(acc))
    return vector(Zq, output)


def trap_gen(n, q, m_bar=None, k=None, gaussian_sigma=3.0):
    """Generate a trapdoor matrix following the MP12 construction."""
    if k is None:
        k = int(ceil(log(q, 2))) + 1
    if m_bar is None:
        m_bar = n * k * 2
    w = n * k
    Zq = Zmod(q)

    G = generate_gadget_matrix(n, k, q)
    A_bar = random_matrix(Zq, n, m_bar)

    sampler = DiscreteGaussianDistributionIntegerSampler(sigma=gaussian_sigma)
    R_entries = [[Integer(sampler()) for _ in range(w)] for _ in range(m_bar)]
    R_int = Matrix(ZZ, R_entries)
    R_mod = Matrix(Zq, m_bar, w, lambda i, j: Zq(R_int[i, j] % q))

    right_block = (A_bar * R_mod + G) % q
    A = block_matrix(Zq, [[A_bar, right_block]])

    return {
        'A': A,
        'A_bar': A_bar,
        'R_int': R_int,
        'R_mod': R_mod,
        'G': G,
        'm_bar': m_bar,
        'w': w,
        'k': k,
    }


def sample_preimage(A_bar, R_int, G, u, q, sigma, R_mod=None, H=None):
    """Compute a lattice preimage solving [A_bar | *] * x = u (mod q)."""  # noqa: E501
    Zq = Zmod(q)
    if R_mod is None:
        R_mod = Matrix(Zq, R_int.nrows(), R_int.ncols(), lambda i, j: Zq(R_int[i, j] % q))

    if H is None:
        effective_right = (A_bar * R_mod + G) % q
    else:
        effective_right = (A_bar * R_mod + H * G) % q

    A_full = A_bar.augment(effective_right)
    solution = A_full.solve_right(u)
    if solution is None:
        raise ValueError("No preimage found for the given vector")

    x_concat_mod = vector(Zq, solution)
    x_concat_int = vector(ZZ, [Integer(coeff) for coeff in solution])
    return x_concat_mod, x_concat_int


def sample_left(A, A_bar, R_int, R_mod, G, B, u, q, sigma):
    """Sample from the lattice defined by [A | B] using the trapdoor for A."""
    Zq = Zmod(q)
    ell = B.ncols()

    if ell:
        z = discrete_gaussian_vector(ell, sigma)
        z_mod = vector(Zq, [Zq(val % q) for val in z])
        u_prime = (u - B * z_mod) % q
    else:
        z_mod = vector(Zq, [])
        u_prime = u

    x_mod, _ = sample_preimage(A_bar, R_int, G, u_prime, q, sigma, R_mod=R_mod)
    return vector(Zq, list(x_mod) + list(z_mod))
