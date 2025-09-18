from sage.all import Zmod, Matrix

def generate_gadget_matrix(n, k, q):
    """Generates the gadget matrix G."""
    Zq = Zmod(q)
    g_t = [2**i for i in range(k)]
    G = Matrix(Zq, n, n * k)
    for i in range(n):
        for j in range(k):
            G[i, i * k + j] = g_t[j] % q
    return G