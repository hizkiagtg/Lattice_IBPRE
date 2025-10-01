from sage.all import (
    Zmod,
    Matrix,
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