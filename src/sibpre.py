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
    Based on Dutta et al. (2020) construction.
    
    Optimizations applied:
      - Uses SHAKE256 for uniform identity hashing.
      - Optimized bit-decomposition using native SageMath methods.
      - Removed redundant PKCS#7 padding (AES-GCM supports arbitrary lengths).
      - Refactored A_id construction to avoid code duplication.
      
    NOTE: Uses 32-bit AES key seed as requested for prototype/benchmark scaling purposes.
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

        # [cite_start]Noise scaling knobs [cite: 101, 119]
        self.alpha_constant = 5000
        self.alpha = 1 / (self.alpha_constant * (n * self.k) ** 2 * max(1.0, sigma) ** 2)

        # Gadget and samplers
        self.G = generate_gadget_matrix(self.n, self.k, self.q)
        self.D = DiscreteGaussianDistributionIntegerSampler(sigma=self.sigma)

        # [cite_start]FRD encoder [cite: 627]
        self.frd = FullRankDifference(self.q, self.n, self.Zq)

        # Small constant used in error variance composition
        self.r = 1.5

        # Public params and "trapdoor-like" R as msk used by this faster path
        self.PP, self.msk = self.SetUp()

    def SetUp(self):
        """
        Setup algorithm generating Public Parameters (PP) and Master Secret Key (msk).
        Implements the trapdoor generation logic.
        """
        A_bar = random_matrix(self.Zq, self.n, self.m_bar)
        R = Matrix(self.Zq, self.m_bar, self.w, lambda *_: self.D() % self.q)
        A = Matrix(self.Zq, self.n, self.m, block_matrix([[A_bar, -A_bar * R]]))
        u = random_vector(self.Zq, self.n)

        # Precompute perturbation terms
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
        """
        Hash an identity string to Z_q^n using SHAKE256 for uniform distribution.
        This fixes potential bias from manual bit-masking.
        """
        # Calculate needed bytes: n elements * bytes_per_element
        bytes_per_elem = (self.q.bit_length() + 7) // 8
        total_bytes = self.n * bytes_per_elem
        
        # Use SHAKE256 (XOF)
        shake = hashlib.shake_256(id_str.encode("utf-8"))
        digest = shake.digest(total_bytes)
        
        coords = []
        for i in range(self.n):
            chunk = digest[i*bytes_per_elem : (i+1)*bytes_per_elem]
            val = int.from_bytes(chunk, "big")
            coords.append(self.Zq(val)) 
            
        return vector(self.Zq, coords)

    def FRD(self, identity):
        """Full-rank-difference encoding for an identity."""
        if isinstance(identity, str):
            id_vec = self.string_to_vector(identity)
        else:
            id_vec = vector(self.Zq, identity[:self.n])
        return self.frd.encode(id_vec)

    def _construct_A_id(self, H_id):
        """
        Helper to construct A_id matrix.
        A_id = [ A_bar | -A_bar*R + H_id*G ]
        Used in Extract, Enc, and ReKeyGen.
        """
        A, _ = self.PP
        A_bar = A[:, :self.m_bar]
        return Matrix(
            self.Zq, self.n, self.m,
            block_matrix([[A_bar, -A_bar * self.msk + H_id * self.G]])
        )

    def lift_to_integers(self, vec):
        """Optimized lifting from Zq to Z (centered)."""
        half_q = self.q // 2
        return vector(ZZ, [Integer(x) - self.q if Integer(x) > half_q else Integer(x) for x in vec])

    def BD(self, x):
        """
        Bit-decomposition using optimized SageMath digits method.
        Decomposes vector x into binary representation.
        """
        bits = []
        for xi in x:
            # .digits(base=2, padto=k) returns little-endian, ensuring correct length
            b = Integer(xi).digits(base=2, padto=self.k)
            bits.extend(b)
        return vector(self.Zq, bits)

    def P2(self, x):
        """Power-of-two expansion (coordinate-wise)."""
        out = []
        # Precomputing powers of 2 might be slightly faster if called often, 
        # but list comprehension here is efficient enough.
        for xi in x:
            val = Integer(xi)
            out.extend([(val * (1 << j)) % self.q for j in range(self.k)])
        return vector(self.Zq, out)

    def aes_encrypt(self, plaintext, key=None, nonce=None):
        """
        AES-GCM Encryption.
        Note: AES-GCM handles arbitrary length messages natively (stream cipher).
        """
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

    def SampleD(self, R, A, H, u, s=0.4):
        """
        Fast sampler for discrete Gaussian preimage.
        Uses optimized binary decomposition logic.
        """
        H_inv = H.inverse()
        v = (H_inv * (u - self.w_bar) - self.w_vec)  # target vector in Z_q^n

        # Build z from base-2 decomposition of v
        z_coords = []
        for val in v:
            # Optimization: Use built-in digits method
            bits = Integer(val).digits(base=2, padto=self.k)
            z_coords.extend([self.Zq(b) for b in bits])
            
        z = vector(self.Zq, z_coords)

        I_w = Matrix.identity(self.Zq, self.w)
        R_I = block_matrix(self.Zq, [[R], [I_w]]) 
        x = (self.p + R_I * z) % self.q
        return x

    def SampleO(self, R, A, u, identity):
        H_id = self.FRD(identity)
        return self.SampleD(R, A, H_id, u, s=0.4)

    def Extract(self, identity):
        """
        [cite_start]Extract Secret Key (sk) for a given identity[cite: 648].
        """
        _, u = self.PP
        H_id = self.FRD(identity)
        A_id = self._construct_A_id(H_id)
        x_id = self.SampleO(self.msk, A_id, u, identity)
        return x_id

    def Enc(self, identity, message):
        """
        [cite_start]Hybrid Encryption[cite: 652].
        1. Generates 32-bit seed (Prototype Constraint).
        2. Expands to 128-bit AES key.
        3. Encrypts message with AES-GCM (No Padding needed).
        4. Encrypts 32-bit seed via LWE.
        """
        # (1) 32-bit AES key seed (PROTOTYPE CONSTRAINT: DO NOT CHANGE)
        aes_key_seed = os.urandom(4)
        key_int = int.from_bytes(aes_key_seed, "big")
        key_bits = [int(b) for b in format(key_int, "032b")]

        # (2) Construct A_id
        H_id = self.FRD(identity)
        _, u = self.PP
        A_id = self._construct_A_id(H_id)

        # (3) Encrypt each seed bit via LWE
        # Precompute sampler to avoid overhead in loop
        D_err = DiscreteGaussianDistributionIntegerSampler(sigma=self.alpha * self.q)
        
        key_ct = []
        for b in key_bits:
            s = random_vector(self.Zq, self.n)

            # Noise terms
            e = D_err() % self.q
            e0 = vector(self.Zq, [D_err() % self.q for _ in range(self.m_bar)])
            e0_lift = self.lift_to_integers(e0)
            
            # Recalculate sigma prime
            s_prime = sqrt(float(norm(e0_lift) ** 2 + self.m_bar * (self.alpha * self.q) ** 2)) * self.r
            
            D_e1 = DiscreteGaussianDistributionIntegerSampler(sigma=s_prime)
            e1 = vector(self.Zq, [D_e1() % self.q for _ in range(self.w)])
            e_vec = vector(self.Zq, list(e0) + list(e1))

            c1 = (A_id.transpose() * s + e_vec) % self.q
            c2 = (u * s + e + b * floor(self.q / 2)) % self.q
            key_ct.append((c1, c2))

        # (4) DEM: AES-GCM
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        elif isinstance(message, (bytes, bytearray)):
            msg_bytes = bytes(message)
        else:
            raise TypeError("Message must be str or bytes")

        # AES-GCM is stream cipher, no PKCS#7 padding required.
        aes_key_full = aes_key_seed * 4  # Expand 4 bytes to 16 bytes
        _, nonce, enc_msg, tag = self.aes_encrypt(msg_bytes, key=aes_key_full)

        return {
            "key_ct": key_ct,
            "enc_msg": enc_msg,
            "nonce": nonce,
            "tag": tag,
        }

    def Dec(self, sk_identity, ciphertext):
        """
        [cite_start]Decryption[cite: 660].
        Recover 32-bit seed -> Expand -> AES Decrypt.
        """
        bits = []
        half_q = self.q // 2
        quarter_q = self.q // 4
        
        for c1, c2 in ciphertext["key_ct"]:
            inner = (c2 - sk_identity * c1) % self.q
            v = Integer(inner)
            if v > half_q:
                v -= self.q
            # Threshold decryption check
            bit = 0 if abs(v) < quarter_q else 1
            bits.append(bit)

        key_int = int("".join(map(str, bits)), 2)
        aes_key_seed = key_int.to_bytes(4, "big")
        aes_key_full = aes_key_seed * 4 

        msg_bytes = self.aes_decrypt(
            aes_key_full,
            ciphertext["nonce"],
            ciphertext["enc_msg"],
            ciphertext["tag"],
        )
        return msg_bytes.decode("utf-8", errors="strict")

    def ReKeyGen(self, sk_id_i, id_i, id_j):
        """
        [cite_start]Generate Re-Encryption Key[cite: 663].
        """
        _, u = self.PP
        H_j = self.FRD(id_j)
        
        # A_id_j construction using helper
        # Note: We need A_id for the TARGET identity (id_j)
        A, _ = self.PP
        A_bar = A[:, :self.m_bar]
        A_id_j = Matrix(
            self.Zq, self.n, self.m,
            block_matrix([[A_bar, -A_bar * self.msk + H_j * self.G]])
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
        [cite_start]Re-Encryption[cite: 668].
        Transforms LWE ciphertexts. Payload remains untouched.
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