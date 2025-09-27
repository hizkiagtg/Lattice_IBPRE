from sage.all import Matrix, vector, random_matrix


class FullRankDifference:
    """Encode identities into full-rank matrices following the FRD paradigm."""

    def __init__(self, q, n, Zq, seed=None):
        self.q = q
        self.n = n
        self.Zq = Zq
        self.base_matrix = self._sample_full_rank()
        self.matrices = [self._sample_full_rank() for _ in range(n)]

    def _sample_full_rank(self):
        candidate = random_matrix(self.Zq, self.n, self.n)
        while candidate.rank() < self.n:
            candidate = random_matrix(self.Zq, self.n, self.n)
        return candidate

    def encode(self, id_vec):
        """Return H_id = B + sum_i id_i * F_i ensuring full rank."""
        id_vec = vector(self.Zq, id_vec[: self.n])
        H = Matrix(self.base_matrix)
        for coeff, matrix in zip(id_vec, self.matrices):
            H += coeff * matrix
        while H.rank() < self.n:
            H += self._sample_full_rank()
        return H
