from sage.all import (
    ZZ, Zmod, Matrix, vector, ceil, log, sqrt, random_vector, floor,
    random_matrix, Integer, block_matrix, norm
)
from sage.stats.distributions.discrete_gaussian_integer import (
    DiscreteGaussianDistributionIntegerSampler
)
from Crypto.Cipher import AES
import os
import hashlib

# Local application imports
from .frd import FullRankDifference
from .utils import generate_gadget_matrix


class SIBPRE:
    """
    SIBPRE (Selective/Strongly Identity-Based Proxy Re-Encryption) — lattice variant.
    This version uses a faster sampling path and a hybrid KEM/DEM:
      - KEM: LWE encrypts a random 128-bit AES key (always 16 bytes).
      - DEM: AES-GCM with PKCS#7 padding handles arbitrary-length messages.
    """

    def __init__(self, n=10, q=65537, sigma=0.5):
        # Core lattice params
        self.n = n
        self.q = q
        self.Zq = Zmod(q)
        self.k = int(ceil(log(q, 2)))
        self.m_bar = 6 * n * self.k
        self.w = n * self.k
        self.m = self.m_bar + self.w
        self.sigma = sigma

        # Noise scaling knobs
        self.alpha_constant = 5000
        self.alpha = 1 / (self.alpha_constant * (n * self.k) ** 2 * max(1.0, sigma) ** 2)

        # Gadget and samplers
        self.G = generate_gadget_matrix(self.n, self.k, self.q)
        self.D = DiscreteGaussianDistributionIntegerSampler(sigma=self.sigma)

        # FRD encoder
        self.frd = FullRankDifference(self.q, self.n, self.Zq)

        # Small constant used in error variance composition
        self.r = 1.5  # effective scale factor (kept from your faster sampler path)

        # Public params and "trapdoor-like" R as msk used by this faster path
        self.PP, self.msk = self.SetUp()


    def SetUp(self):
        """
        Faster (trapdoor-light) setup:
          - A = [ A_bar | -A_bar * R ]
          - public u ∈ Z_q^n
          - perturbation vector p produces w_bar, w_vec (used by the sampler)
        """
        A_bar = random_matrix(self.Zq, self.n, self.m_bar)
        R = Matrix(self.Zq, self.m_bar, self.w, lambda *_: self.D() % self.q)
        A = Matrix(self.Zq, self.n, self.m, block_matrix([[A_bar, -A_bar * R]]))
        u = random_vector(self.Zq, self.n)

        # Precompute perturbation terms (kept from your faster approach)
        sqrt_Sigma_G = 2
        D_pert = DiscreteGaussianDistributionIntegerSampler(sigma=self.r * sqrt_Sigma_G)
        p_int = vector(ZZ, [D_pert() for _ in range(self.m)])
        self.p = vector(self.Zq, p_int)

        p1 = self.p[:self.m_bar]
        p2 = self.p[self.m_bar:]
        Rp2 = (R * p2) % self.q
        self.w_bar = (A_bar * (p1 - Rp2)) % self.q
        self.w_vec = (self.G * p2) % self.q

        return (A, u), R

    def string_to_vector(self, id_str):
        """Hash an identity string to Z_q^n."""
        h = hashlib.sha256(id_str.encode("utf-8")).digest()
        hint = int.from_bytes(h, "big")
        chunk = hint.bit_length() // self.n + 1
        coords, tmp = [], hint
        for _ in range(self.n):
            c = tmp & ((1 << chunk) - 1)
            coords.append(self.Zq(c % self.q))
            tmp >>= chunk
        while len(coords) < self.n:
            coords.append(self.Zq(0))
        return vector(self.Zq, coords)

    def FRD(self, identity):
        """Full-rank-difference encoding for an identity."""
        if isinstance(identity, str):
            id_vec = self.string_to_vector(identity)
        else:
            id_vec = vector(self.Zq, identity[:self.n])
        return self.frd.encode(id_vec)

    def lift_to_integers(self, vec):
        lifted = []
        for x in vec:
            xi = Integer(x)
            if xi > self.q // 2:
                xi -= self.q
            lifted.append(xi)
        return vector(ZZ, lifted)

    def BD(self, x):
        """Bit-decomposition (coordinate-wise, padded to k bits)."""
        bits = []
        for xi in x:
            b = Integer(xi).bits()
            bits.extend(b + [0] * (self.k - len(b)))
        return vector(self.Zq, bits)

    def P2(self, x):
        """Power-of-two expansion (coordinate-wise)."""
        out = []
        for xi in x:
            out.extend([xi * (2 ** j) % self.q for j in range(self.k)])
        return vector(self.Zq, out)

    def aes_encrypt(self, plaintext, key=None, nonce=None):
        if key is None:
            key = os.urandom(16)  
        if nonce is None:
            nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return key, nonce, ciphertext, tag

    def aes_decrypt(self, key, nonce, ciphertext, tag):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def _pkcs7_pad(self, data, block_size=16):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    def _pkcs7_unpad(self, data):
        if not data:
            return data
        pad_len = data[-1]
        if pad_len == 0 or pad_len > len(data):
            raise ValueError("Invalid PKCS7 padding")
        if any(b != pad_len for b in data[-pad_len:]):
            raise ValueError("Invalid PKCS7 padding")
        return data[:-pad_len]


    def SampleD(self, R, A, H, u, s=0.4):
        """
        Fast sampler that avoids full trapdoor usage.
        Approximates a short preimage using precomputed (w_bar, w_vec, p).
        """
        H_inv = H.inverse()
        v = (H_inv * (u - self.w_bar) - self.w_vec)  # target vector in Z_q^n

        # Build z from base-2 decomposition of v (greedy, mod q)
        z = vector(self.Zq, self.w)
        g_t = [2 ** j for j in range(self.k)]
        for i in range(self.n):
            target = v[i]
            z_i = [self.Zq(0)] * self.k
            for j in range(self.k - 1, -1, -1):
                power = g_t[j]
                # multiply by inverse of power (mod q)
                coeff = Integer(target) * pow(power, -1, self.q)
                z_i[j] = self.Zq(coeff)
                target = (target - z_i[j] * power)
            for j in range(self.k):
                z[i * self.k + j] = z_i[j]

        I_w = Matrix.identity(self.Zq, self.w)
        R_I = block_matrix(self.Zq, [[R], [I_w]])  # shape: (m_bar + w) x w == m x w
        x = (self.p + R_I * z) % self.q
        return x

    def SampleO(self, R, A, u, identity):
        H_id = self.FRD(identity)
        return self.SampleD(R, A, H_id, u, s=0.4)

    def Extract(self, identity):
        """
        Secret key for identity:
          x_id ← SampleO on A_id constructed from FRD(H_id).
        """
        A, u = self.PP
        H_id = self.FRD(identity)
        # A_id = [ A_bar | -A_bar*R + H_id*G ]
        A_id = Matrix(
            self.Zq, self.n, self.m,
            block_matrix([[A[:, :self.m_bar], -A[:, :self.m_bar] * self.msk + H_id * self.G]])
        )
        x_id = self.SampleO(self.msk, A_id, u, identity)
        return x_id

    def Enc(self, identity, message):
        """
        Hybrid encryption:
          1) Generate random 128-bit AES key.
          2) Encrypt arbitrary-length message (bytes or UTF-8 str) with AES-GCM (+PKCS#7).
          3) LWE-encrypt the AES key bits (length fixed to 128).
        """
        # (1) 128-bit AES key 
        aes_key = os.urandom(16)
        key_int = int.from_bytes(aes_key, "big")
        key_bits = [int(b) for b in format(key_int, "0128b")]

        # (2) Build identity-specific A_id
        A, u = self.PP
        H_id = self.FRD(identity)
        A_id = Matrix(
            self.Zq, self.n, self.m,
            block_matrix([[A[:, :self.m_bar], -A[:, :self.m_bar] * self.msk + H_id * self.G]])
        )

        # (3) Encrypt each key bit via LWE
        key_ct = []
        for b in key_bits:
            s = random_vector(self.Zq, self.n)

            # Noise terms (fast path)
            D_err = DiscreteGaussianDistributionIntegerSampler(sigma=self.alpha * self.q)
            e = D_err() % self.q
            e0 = vector(self.Zq, [D_err() % self.q for _ in range(self.m_bar)])
            e0_lift = self.lift_to_integers(e0)
            s_prime = sqrt(float(norm(e0_lift) ** 2 + self.m_bar * (self.alpha * self.q) ** 2)) * self.r
            D_e1 = DiscreteGaussianDistributionIntegerSampler(sigma=s_prime)
            e1 = vector(self.Zq, [D_e1() % self.q for _ in range(self.w)])
            e_vec = vector(self.Zq, list(e0) + list(e1))

            c1 = (A_id.transpose() * s + e_vec) % self.q
            c2 = (u * s + e + b * floor(self.q / 2)) % self.q
            key_ct.append((c1, c2))

        # (4) DEM: AES-GCM over arbitrary-length message
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        elif isinstance(message, (bytes, bytearray)):
            msg_bytes = bytes(message)
        else:
            raise TypeError("Message must be str or bytes")

        padded = self._pkcs7_pad(msg_bytes)
        _, nonce, enc_msg, tag = self.aes_encrypt(padded, key=aes_key)

        return {
            "key_ct": key_ct,
            "enc_msg": enc_msg,
            "nonce": nonce,
            "tag": tag,
        }

    def Dec(self, sk_identity, ciphertext):
        """
        Reconstruct the 128-bit AES key from LWE key_ct, then AES-GCM decrypt and unpad.
        """
        bits = []
        for c1, c2 in ciphertext["key_ct"]:
            inner = (c2 - sk_identity * c1) % self.q
            v = Integer(inner)
            if v > self.q // 2:
                v -= self.q
            bit = 0 if abs(v) < self.q // 4 else 1
            bits.append(bit)

        key_int = int("".join(map(str, bits)), 2)
        aes_key = key_int.to_bytes(16, "big")

        padded = self.aes_decrypt(
            aes_key,
            ciphertext["nonce"],
            ciphertext["enc_msg"],
            ciphertext["tag"],
        )
        msg = self._pkcs7_unpad(padded)
        return msg.decode("utf-8", errors="strict")

    def ReKeyGen(self, sk_id_i, id_i, id_j):
        """
        Generate re-encryption key rk_{i->j} using fast-noise path.
        """
        A, u = self.PP
        H_j = self.FRD(id_j)
        A_id_j = Matrix(
            self.Zq, self.n, self.m,
            block_matrix([[A[:, :self.m_bar], -A[:, :self.m_bar] * self.msk + H_j * self.G]])
        )

        D_r = DiscreteGaussianDistributionIntegerSampler(sigma=max(2.0, self.sigma) / 2)
        r1 = Matrix(self.Zq, self.m * self.k, self.n, lambda *_: D_r() % self.q)
        r2 = vector(self.Zq, [D_r() % self.q for _ in range(self.m * self.k)])

        top_left = (r1 * A_id_j) % self.q
        top_right = (r1 * u + r2 - self.P2(sk_id_i)) % self.q
        rk = block_matrix(
            self.Zq,
            [
                [top_left, Matrix(self.Zq, self.m * self.k, 1, list(top_right))],
                [Matrix(self.Zq, 1, self.m, [0] * self.m), Matrix(self.Zq, 1, 1, [1])],
            ],
        )
        return rk

    def ReEnc(self, rk, ciphertext):
        """
        Transform key ciphertexts using rk; payload remains unchanged.
        """
        re_key_ct = []
        for c1, c2 in ciphertext["key_ct"]:
            bd_c1 = self.BD(c1)
            vec = vector(self.Zq, list(bd_c1) + [c2])
            ct_bar = (vec * rk) % self.q
            re_key_ct.append((ct_bar[: self.m], ct_bar[self.m]))

        return {
            "key_ct": re_key_ct,
            "enc_msg": ciphertext["enc_msg"],
            "nonce": ciphertext["nonce"],
            "tag": ciphertext["tag"],
        }
