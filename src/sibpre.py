from sage.all import (
    ZZ,
    Zmod,
    Matrix,
    vector,
    ceil,
    log,
    random_vector,
    floor,
    Integer,
    block_matrix,
)
from sage.stats.distributions.discrete_gaussian_integer import (
    DiscreteGaussianDistributionIntegerSampler,
)
from Crypto.Cipher import AES
import os
import hashlib

from .frd import FullRankDifference
from .utils import trap_gen, sample_preimage


class SIBPRE:
    """Implementation of the lattice-based IB-PRE scheme following MP12 trapdoors."""  # noqa: E501

    def __init__(self, n=10, q=65537, sigma=0.5):
        self.n = n
        self.q = q
        self.Zq = Zmod(q)
        self.k = int(ceil(log(q, 2))) + 1
        self.m_bar = 6 * n * self.k
        self.w = n * self.k
        self.sigma = sigma
        self.sample_sigma = max(4.0, sigma * (self.m_bar ** 0.5))
        self.error_sigma = max(4.0, sigma * (self.n ** 0.5))
        self.alpha_constant = 5000
        self.alpha = 1 / (self.alpha_constant * (n * self.k) ** 2 * max(1.0, sigma) ** 2)

        trap_info = trap_gen(self.n, self.q, m_bar=self.m_bar, k=self.k, gaussian_sigma=self.sample_sigma)  # noqa: E501
        self.A = trap_info['A']
        self.A_bar = trap_info['A_bar']
        self.R_int = trap_info['R_int']
        self.R_mod = trap_info['R_mod']
        self.G = trap_info['G']
        self.m = self.A.ncols()

        self.frd = FullRankDifference(self.q, self.n, self.Zq)
        self.PP, self.msk = self.SetUp()

    def SetUp(self):
        u = random_vector(self.Zq, self.n)
        public_params = (self.A, u)
        master_secret = {'R_int': self.R_int, 'R_mod': self.R_mod}
        return public_params, master_secret

    
    def string_to_vector(self, id_str):
        hash_obj = hashlib.sha256(id_str.encode('utf-8'))
        hash_int = int.from_bytes(hash_obj.digest(), byteorder='big')
        chunk_size = hash_int.bit_length() // self.n + 1
        coords = []
        temp = hash_int
        for _ in range(self.n):
            chunk = temp & ((1 << chunk_size) - 1)
            coords.append(self.Zq(chunk % self.q))
            temp >>= chunk_size
        while len(coords) < self.n:
            coords.append(self.Zq(0))
        return vector(self.Zq, coords)

    def FRD(self, identity):
        if isinstance(identity, str):
            id_vec = self.string_to_vector(identity)
        else:
            id_vec = vector(self.Zq, identity[: self.n])
        return self.frd.encode(id_vec)

    def lift_to_integers(self, vec):
        lifted = []
        for entry in vec:
            value = Integer(entry)
            if value > self.q // 2:
                value -= self.q
            lifted.append(value)
        return vector(ZZ, lifted)

    def matrix_for_identity(self, identity):
        H_id = self.FRD(identity)
        second_block = (self.A_bar * self.R_mod + H_id * self.G) % self.q
        A_id = block_matrix(self.Zq, [[self.A_bar, second_block]])
        return A_id, H_id

    def SampleD(self, H_matrix, u_vector, sigma=None):
        """Sample a short preimage for identity-specific matrices."""
        sigma_eff = sigma or self.sample_sigma
        x_mod, x_int = sample_preimage(
            self.A_bar,
            self.R_int,
            self.G,
            u_vector,
            self.q,
            sigma_eff,
            R_mod=self.R_mod,
            H=H_matrix,
        )
        return x_mod, x_int

    def SampleO(self, identity, u_vector, sigma=None):
        """Convenience wrapper following MP12 SampleO without random oracles."""
        H_id = self.FRD(identity)
        return self.SampleD(H_id, u_vector, sigma=sigma)


    def Extract(self, identity):
        A_id, H_id = self.matrix_for_identity(identity)
        _, u = self.PP
        sk_mod, _ = self.SampleD(H_id, u)
        return sk_mod

    def Enc(self, identity, message):
        if not isinstance(message, str):
            raise TypeError("Message must be a UTF-8 string")
        message_bytes = message.encode('utf-8')
        padded = self._pkcs7_pad(message_bytes)
        aes_key, nonce, enc_msg, tag = self.aes_encrypt(padded)
        key_bits = [int(bit) for bit in format(int.from_bytes(aes_key, 'big'), '0128b')]

        A_id, _ = self.matrix_for_identity(identity)
        _, u = self.PP

        key_ciphertexts = []
        for bit in key_bits:
            s = random_vector(self.Zq, self.n)
            e_vec = vector(self.Zq, [self.Zq(0) for _ in range(self.m)])
            e = self.Zq(0)
            c1 = (A_id.transpose() * s + e_vec) % self.q
            c2 = (u * s + e + bit * floor(self.q / 2)) % self.q
            key_ciphertexts.append((c1, c2))

        return {
            'key_ct': key_ciphertexts,
            'enc_msg': enc_msg,
            'nonce': nonce,
            'tag': tag,
        }

    def Dec(self, sk_identity, ciphertext):
        key_bits = []
        for c1, c2 in ciphertext['key_ct']:
            inner = (c2 - sk_identity * c1) % self.q
            lifted = Integer(inner)
            if lifted > self.q // 2:
                lifted -= self.q
            bit = 0 if abs(lifted) < self.q // 4 else 1
            key_bits.append(bit)

        key_int = int(''.join(map(str, key_bits)), 2)
        aes_key = key_int.to_bytes(16, 'big')
        padded = self.aes_decrypt(
            aes_key,
            ciphertext['nonce'],
            ciphertext['enc_msg'],
            ciphertext['tag'],
        )
        message_bytes = self._pkcs7_unpad(padded)
        return message_bytes.decode('utf-8')

    def BD(self, vector_input):
        bits = []
        for coord in vector_input:
            b = Integer(coord).bits()
            bits.extend(b + [0] * (self.k - len(b)))
        return vector(self.Zq, bits)

    def P2(self, vector_input):
        powers = []
        for coord in vector_input:
            powers.extend([coord * (2 ** j) % self.q for j in range(self.k)])
        return vector(self.Zq, powers)

    def ReKeyGen(self, sk_identity_i, identity_i, identity_j):
        A_id_j, _ = self.matrix_for_identity(identity_j)
        _, u = self.PP
        gaussian = DiscreteGaussianDistributionIntegerSampler(sigma=max(2.0, self.sigma))

        r1 = Matrix(self.Zq, self.m * self.k, self.n, lambda *_: self.Zq(gaussian() % self.q))
        r2 = vector(self.Zq, [self.Zq(gaussian() % self.q) for _ in range(self.m * self.k)])

        top_left = (r1 * A_id_j) % self.q
        top_right = (r1 * u + r2 - self.P2(sk_identity_i)) % self.q
        rk = block_matrix(
            self.Zq,
            [
                [top_left, Matrix(self.Zq, self.m * self.k, 1, list(top_right))],
                [Matrix(self.Zq, 1, self.m, [0] * self.m), Matrix(self.Zq, 1, 1, [1])],
            ],
        )
        return rk

    def ReEnc(self, rekey, ciphertext):
        new_key_ct = []
        for c1, c2 in ciphertext['key_ct']:
            bd_c1 = self.BD(c1)
            vec = vector(self.Zq, list(bd_c1) + [c2])
            transformed = (vec * rekey) % self.q
            new_key_ct.append((transformed[: self.m], transformed[self.m]))

        return {
            'key_ct': new_key_ct,
            'enc_msg': ciphertext['enc_msg'],
            'nonce': ciphertext['nonce'],
            'tag': ciphertext['tag'],
        }


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
        if any(byte != pad_len for byte in data[-pad_len:]):
            raise ValueError("Invalid PKCS7 padding")
        return data[:-pad_len]
