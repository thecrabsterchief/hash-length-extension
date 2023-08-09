from .utils import HASH

class CONST:
    # Initial Hash Value
    H0 = 0xcbbb9d5dc1059ed8
    H1 = 0x629a292a367cd507
    H2 = 0x9159015a3070dd17
    H3 = 0x152fecd8f70e5939
    H4 = 0x67332667ffc00b31
    H5 = 0x8eb44a8768581511
    H6 = 0xdb0c2e0d64f98fa7
    H7 = 0x47b5481dbefa4fa4

    # Magic constants value to be used for each iteration.
    K = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ]

    # Number of bits in a word
    WORD_SIZE = 64

    # The rotate right (circular right shift) operation.
    @classmethod
    def ROTR(cls, x: int, shift: int):
        res = (x >> shift) | (x << cls.WORD_SIZE - shift)
        return res & 0xffffffffffffffff

    # Secured-defined function
    @classmethod
    def Ch(cls, x: int, y: int, z: int):
        res = (x & y) ^ (~x & z)
        return res & 0xffffffffffffffff

    # Secured-defined function
    @classmethod
    def Maj(cls, x: int, y: int, z: int):
        res = (x & y) ^ (x & z) ^ (y & z)
        return res & 0xffffffffffffffff

    # Secured-defined function
    @classmethod
    def sigma0(cls, x: int):
        res = cls.ROTR(x=x, shift=1) ^ cls.ROTR(x=x, shift=8) ^ (x >> 7)
        return res & 0xffffffffffffffff

    # Secured-defined function
    @classmethod
    def sigma1(cls, x: int):
        res = cls.ROTR(x=x, shift=19) ^ cls.ROTR(x=x, shift=61) ^ (x >> 6)
        return res & 0xffffffffffffffff

    # Secured-defined function
    @classmethod
    def SIGMA0(cls, x: int):
        res = cls.ROTR(x=x, shift=28) ^ cls.ROTR(x=x, shift=34) ^ cls.ROTR(x=x, shift=39)
        return res & 0xffffffffffffffff

    # Secured-defined function
    @classmethod
    def SIGMA1(cls, x: int):
        res = cls.ROTR(x=x, shift=14) ^ cls.ROTR(x=x, shift=18) ^ cls.ROTR(x=x, shift=41)
        return res & 0xffffffffffffffff


class SHA384(HASH):
    def __init__(self, message=b"") -> None:
        super().__init__(message=message, block_size=128)        
        self.__digest = self.__hashing()

    def update(self, message=b""):
        super()._update(message=message)
        self.__digest = self.__hashing()

    def digest(self):
        """Return message digest in raw bytes"""

        return self.__digest
    
    def hexdigest(self):
        """Return message digest in hex format"""

        return self.__digest.hex()
    
    def __hashing(self):
        # preprocessing
        padded_message = self._padding(self.original_message)   # padding
        blocks         = self._parsing(padded_message)          # parsing

        # Setting Initial Hash Value
        h0, h1, h2, h3, h4, h5, h6, h7 = [
            CONST.H0, CONST.H1, CONST.H2 , CONST.H3,
            CONST.H4, CONST.H5, CONST.H6 , CONST.H7
        ]

        # SHA-384 Hashing Algorithm
        for message_block in blocks:
            
            ''' Step 1: Prepare the message shedule.
            '''
            W = []
            for t in range(80):
                if t <= 15:
                    W.append(bytes(message_block[8*t: 8*(t + 1)]))

                else:
                    term1 = CONST.sigma1(int.from_bytes(W[t - 2] , byteorder='big'))
                    term2 =              int.from_bytes(W[t - 7] , byteorder='big')
                    term3 = CONST.sigma0(int.from_bytes(W[t - 15], byteorder='big'))
                    term4 =              int.from_bytes(W[t - 16], byteorder='big')

                    schedule = (
                        (term1 + term2 + term3 + term4) & 0xffffffffffffffff
                    ).to_bytes(length=8, byteorder='big')
                    W.append(schedule)
            assert len(W) == 80

            ''' Step 2: Initialize the eight working variables with the   
                    (i-1)-st hash value.
            '''
            a, b, c, d, e, f, g, h = [
                h0, h1, h2, h3, h4, h5, h6, h7
            ]

            ''' Step 3: Iterate for t=0 to 79.
            '''
            for t in range(80):
                T1 = h + CONST.SIGMA1(e) + CONST.Ch(e, f, g) + CONST.K[t] + \
                            int.from_bytes(W[t], byteorder='big')
                T2 = CONST.SIGMA0(a) + CONST.Maj(a, b, c)

                h = g
                g = f
                f = e
                e = (d + T1) & 0xffffffffffffffff
                d = c
                c = b
                b = a
                a = (T1 + T2) & 0xffffffffffffffff
            
            ''' Step 4: Compute the i-th intermediate hash value H(i).
            '''
            h0 = (h0 + a) & 0xffffffffffffffff
            h1 = (h1 + b) & 0xffffffffffffffff
            h2 = (h2 + c) & 0xffffffffffffffff
            h3 = (h3 + d) & 0xffffffffffffffff
            h4 = (h4 + e) & 0xffffffffffffffff
            h5 = (h5 + f) & 0xffffffffffffffff
            h6 = (h6 + g) & 0xffffffffffffffff
            h7 = (h7 + h) & 0xffffffffffffffff
        
        # Resulting 384-bit message digest
        return  (h0).to_bytes(8, byteorder='big') + (h1).to_bytes(8, byteorder='big') + \
                (h2).to_bytes(8, byteorder='big') + (h3).to_bytes(8, byteorder='big') + \
                (h4).to_bytes(8, byteorder='big') + (h5).to_bytes(8, byteorder='big')