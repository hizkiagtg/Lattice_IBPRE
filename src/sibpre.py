from sage.all import (
    ZZ, Zmod, Matrix, vector, ceil, log, sqrt, random_vector, floor,
    random_matrix, Integer, block_matrix, norm
)
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.stats.distributions.discrete_gaussian_lattice import DiscreteGaussianDistributionLatticeSampler
from Crypto.Cipher import AES
import os
import hashlib

# Local application imports
from .frd import FullRankDifference
from .utils import generate_gadget_matrix

class SIBPRE:
    """
    Implements the core logic for the SIBPRE (Strongly Identity-Based Proxy
    Re-Encryption) scheme.
    """
    def __init__(self, n=10, q=65537, sigma=0.5):
        self.n = n
        self.q = q
        self.k = ceil(log(q, 2))
        self.m_bar = 6 * n * self.k
        self.w = n * self.k
        self.m = self.m_bar + self.w
        self.sigma = sigma
        self.alpha_constant = 5000
        self.alpha = 1 / (self.alpha_constant * (n * self.k)**2 * sigma**2)
        self.Zq = Zmod(q)
        self.r = 1
        
        self.G = generate_gadget_matrix(self.n, self.k, self.q)
        self.D = DiscreteGaussianDistributionIntegerSampler(sigma=self.sigma)
        self.frd = FullRankDifference(self.q, self.n, self.Zq)
        self.PP, self.msk = self.SetUp()

    def SetUp(self):
        A_bar = random_matrix(self.Zq, self.n, self.m_bar)
        R = Matrix(self.Zq, self.m_bar, self.w, lambda i, j: self.D() % self.q)
        A = Matrix(self.Zq, self.n, self.m, block_matrix([[A_bar, -A_bar * R]]))
        u = random_vector(self.Zq, self.n)
        
        sqrt_Sigma_G = 2
        r = 1.5
        D_pert = DiscreteGaussianDistributionIntegerSampler(sigma=r * sqrt_Sigma_G)
        self.p = vector(ZZ, [D_pert() for _ in range(self.m)])
        self.p = vector(self.Zq, self.p)
        p1 = self.p[:self.m_bar]
        p2 = self.p[self.m_bar:]
        Rp2 = (R * p2) % self.q
        self.w_bar = (A_bar * (p1 - Rp2)) % self.q
        self.w_vec = (self.G * p2) % self.q

        return (A, u), R

    def string_to_vector(self, id_str):
        """Convert a string identity to a vector in Zq^n by hashing."""
        hash_obj = hashlib.sha256(id_str.encode('utf-8'))
        hash_int = int.from_bytes(hash_obj.digest(), byteorder='big')
        
        chunk_size = hash_int.bit_length() // self.n + 1
        id_vec = []
        temp_int = hash_int
        for _ in range(self.n):
            chunk = temp_int & ((1 << chunk_size) - 1)
            id_vec.append(self.Zq(chunk % self.q))
            temp_int >>= chunk_size
        while len(id_vec) < self.n:
            id_vec.append(self.Zq(0))
        return vector(self.Zq, id_vec)

    def FRD(self, id_vec):
        if isinstance(id_vec, str):
            id_vec = self.string_to_vector(id_vec)
        return self.frd.encode(id_vec)

    def BD(self, x):
        bits = []
        for xi in x:
            b = Integer(xi).bits()
            bits.extend(b + [0] * (self.k - len(b)))
        return vector(self.Zq, bits)

    def P2(self, x):
        result = []
        for xi in x:
            result.extend([xi * (2**j) % self.q for j in range(self.k)])
        return vector(self.Zq, result)
    
    def lift_to_integers(self, vec):
        lifted = []
        for x in vec:
            x_int = Integer(x)
            if x_int > self.q // 2:
                x_int -= self.q
            lifted.append(x_int)
        return vector(ZZ, lifted)

    def SampleD(self, R, A, H, u, s):
        H_inv = H.inverse()
        v = (H_inv * (u - self.w_bar) - self.w_vec)
        z = vector(self.Zq, self.w)
        g_t = [2**i for i in range(self.k)]
        
        sqrt_Sigma_G = 2
        r = 1.5

        for i in range(self.n):
            v_i = v[i]
            z_i = vector(ZZ, self.k)
            target = v_i
            for j in range(self.k - 1, -1, -1):
                power = g_t[j]
                coeff = Integer(target) * pow(power, -1, self.q)
                z_i[j] = self.Zq(coeff)
                target = (target - z_i[j] * power)
            
            for j in range(self.k):
                z[i * self.k + j] = z_i[j]

        I_w = Matrix.identity(self.Zq, self.w)
        R_I = block_matrix(self.Zq, [[R], [I_w]])
        x = (self.p + R_I * z) % self.q
        return x

    def SampleO(self, R, A, u, id_vec):
        H_id = self.FRD(id_vec)
        s = 0.4
        return self.SampleD(R, A, H_id, u, s)

    def Extract(self, id):
        A, u = self.PP
        H_id = self.FRD(id)
        A_id = Matrix(self.Zq, self.n, self.m, block_matrix([[A[:, :self.m_bar], -A[:, :self.m_bar] * self.msk + H_id * self.G]]))
        x_id = self.SampleO(self.msk, A_id, u, id)
        return x_id

    def Enc(self, id, message):
        """Hybrid encryption: Encrypt a 128-bit AES key, then encrypt the message."""
        aes_key = os.urandom(16)
        aes_key_int = int.from_bytes(aes_key, byteorder='big')
        key_bits = [int(bit) for bit in format(aes_key_int, '0128b')]

        A, u = self.PP
        H_id = self.FRD(id)
        A_id = Matrix(self.Zq, self.n, self.m, block_matrix([[A[:, :self.m_bar], -A[:, :self.m_bar] * self.msk + H_id * self.G]]))
        key_ciphertexts = []
        for b in key_bits:
            s = random_vector(self.Zq, self.n)
            D_error = DiscreteGaussianDistributionIntegerSampler(sigma=self.alpha * self.q)
            e = D_error() % self.q
            e0 = vector(self.Zq, [D_error() % self.q for _ in range(self.m_bar)])
            e0_lifted = self.lift_to_integers(e0)
            s_prime = sqrt(float(norm(e0_lifted)**2 + self.m_bar * (self.alpha * self.q)**2)) * self.r
            D_e1 = DiscreteGaussianDistributionIntegerSampler(sigma=s_prime)
            e1 = vector(self.Zq, [D_e1() % self.q for _ in range(self.w)])
            e_vec = vector(self.Zq, list(e0) + list(e1))
            c1 = (A_id.transpose() * s + e_vec) % self.q
            c2 = (u * s + e + b * floor(self.q / 2)) % self.q
            key_ciphertexts.append((c1, c2))

        if len(message) != 2:
            raise ValueError("Message must be exactly 2 bytes (16 bits)")
        message_bytes = message.encode('utf-8')

        padding_length = 16 - (len(message_bytes) % 16)
        padding = bytes([padding_length] * padding_length)
        padded_message = message_bytes + padding
        
        nonce = os.urandom(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        encrypted_message, tag = cipher.encrypt_and_digest(padded_message)

        return {'key_ct': key_ciphertexts, 'enc_msg': encrypted_message, 'nonce': nonce, 'tag': tag}

    def Dec(self, sk_id, ciphertext):
        """Decrypt the AES key, then decrypt the message."""
        key_ciphertexts = ciphertext['key_ct']
        key_bits = []
        for ct in key_ciphertexts:
            c1, c2 = ct
            b_prime = (c2 - sk_id * c1) % self.q
            b_prime_lifted = Integer(b_prime)
            if b_prime_lifted > self.q // 2:
                b_prime_lifted -= self.q
            bit = 0 if abs(b_prime_lifted) < self.q // 4 else 1
            key_bits.append(bit)

        key_int = int(''.join(map(str, key_bits)), 2)
        aes_key = key_int.to_bytes(16, byteorder='big')
        
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=ciphertext['nonce'])
        padded_message = cipher.decrypt_and_verify(ciphertext['enc_msg'], ciphertext['tag'])
        
        padding_length = padded_message[-1]
        message_bytes = padded_message[:-padding_length]
        
        return message_bytes.decode('utf-8')

    def ReEnc(self, rk, ciphertext):
        reenc_key_ciphertexts = []
        for ct in ciphertext['key_ct']:
            c1, c2 = ct
            bd_c1 = self.BD(c1)
            vec = vector(self.Zq, list(bd_c1) + [c2])
            ct_bar = (vec * rk) % self.q
            reenc_key_ciphertexts.append((ct_bar[:self.m], ct_bar[self.m]))
        
        return {
            'key_ct': reenc_key_ciphertexts,
            'enc_msg': ciphertext['enc_msg'],
            'nonce': ciphertext['nonce'],
            'tag': ciphertext['tag']
        }

    def ReKeyGen(self, sk_id_i, id_i, id_j):
        A, u = self.PP
        H_id_j = self.FRD(id_j)
        A_id_j = Matrix(self.Zq, self.n, self.m, block_matrix([[A[:, :self.m_bar], -A[:, :self.m_bar] * self.msk + H_id_j * self.G]]))

        D_r = DiscreteGaussianDistributionIntegerSampler(sigma=self.sigma / 2)
        r1 = Matrix(self.Zq, self.m * self.k, self.n, lambda i, j: D_r() % self.q)
        r2 = vector(self.Zq, [D_r() % self.q for _ in range(self.m * self.k)])

        top_left = (r1 * A_id_j)
        top_right = (r1 * u + r2 - self.P2(sk_id_i))
        rk = block_matrix(self.Zq, [
            [top_left, Matrix(self.Zq, self.m * self.k, 1, list(top_right))],
            [Matrix(self.Zq, 1, self.m, [0] * self.m), Matrix(self.Zq, 1, 1, [1])]
        ])
        return rk