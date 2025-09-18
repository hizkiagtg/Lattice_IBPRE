from sage.all import Matrix, vector, random_matrix

class FullRankDifference:
    """
    A class to generate a full-rank difference matrix H_id from an identity vector.
    """
    def __init__(self, q, n, Zq):
        self.q = q
        self.n = n
        self.Zq = Zq
        self.F = random_matrix(self.Zq, n, n)
        while self.F.rank() < n:
            self.F = random_matrix(self.Zq, n, n)

    def encode(self, id_vec):
        """Encodes an identity vector into a matrix H_id."""
        id_vec = vector(self.Zq, id_vec[:self.n])
        scalar = self.Zq(sum(id_vec)) or self.Zq(1)
        H_id = Matrix.identity(self.Zq, self.n) + scalar * self.F
        # Regenerate F if H_id is not full rank to ensure invertibility
        while H_id.rank() < self.n:
            self.F = random_matrix(self.Zq, self.n, self.n)
            while self.F.rank() < self.n:
                self.F = random_matrix(self.Zq, self.n, self.n)
            H_id = Matrix.identity(self.Zq, self.n) + scalar * self.F
        return H_id