from .utils import HASH

class CONST:
    # Initial Hash Value
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    # Magic constants
    K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]

    # Specifies the per-round shift amounts
    S = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]

    WORD_SIZE = 32

    # The rotate left (circular left shift) operation.
    @classmethod
    def ROTL(cls, x: int, shift: int):
        res = (x << shift) | (x >> cls.WORD_SIZE - shift)
        return res & 0xffffffff
    
    # Secured-defined function
    @classmethod
    def F(cls, x: int, y: int, z: int):
        res = (x & y) | (~x & z)
        return res & 0xffffffff

    # Secured-defined function
    @classmethod
    def G(cls, x: int, y: int, z: int):
        res = (x & z) | (y & ~z)
        return res & 0xffffffff

    # Secured-defined function
    @classmethod
    def H(cls, x: int, y: int, z: int):
        res = x ^ y ^ z
        return res & 0xffffffff

    # Secured-defined function
    @classmethod
    def I(cls, x: int, y: int, z: int):
        res = y ^ (x | ~z)
        return res & 0xffffffff

class MD5(HASH):
    def __init__(self, message=b"") -> None:
        super().__init__(message, block_size=64)
        self.digest = self._hashing()

    def update(self, message=b""):
        super()._update(message=message)
        self.digest = self._hashing()

    # md5 use little endian
    def _padding(self):
        # Get current message
        message = self.original_message

        # Padding the Message
        bit_length = len(message) * 8
        message += b"\x80" 
        while (len(message) * 8 + self.BLOCK_SIZE) % (self.BLOCK_SIZE * 8):
            message += b"\x00"
        
        message += bit_length.to_bytes(
            length=self.BLOCK_SIZE//8, byteorder='little'
        )

        assert len(message) % self.BLOCK_SIZE == 0, \
                "Something goes wrong when padding!"
    
        return message
    
    def _hashing(self):
        # preprocessing
        padded_message = self._padding()                # padding
        blocks         = self._parsing(padded_message)  # parsing

        # Setting Initial Hash Value
        a0, b0, c0, d0 = [
            CONST.A, CONST.B, CONST.C, CONST.D
        ]

        # md5 Hashing Algorithm
        for message_block in blocks:
            
            ''' Step 1: Prepare the message shedule.
            '''
            W = []
            for t in range(64):
                W.append(bytes(message_block[4*t: 4*(t + 1)]))
            
            ''' Step 2: Initialize the eight working variables with the   
                    (i-1)-st hash value.
            '''
            a, b, c, d = a0, b0 , c0, d0

            ''' Step 3: Iterate for i=0 to 63.
            '''
            for i in range(64):
                if i <= 15:
                    F = CONST.F(b, c, d)
                    g = i
                elif i <= 31:
                    F = CONST.G(b, c, d)
                    g = (5*i + 1) % 16
                elif i <= 47:
                    F = CONST.H(b, c, d)
                    g = (3*i + 5) % 16
                else:
                    F = CONST.I(b, c, d)
                    g = (7*i) % 16
            
                F = (F + a + CONST.K[i] + int.from_bytes(W[g], byteorder='little')) & 0xffffffff
                a = d
                d = c
                c = b
                b = (b + CONST.ROTL(F, CONST.S[i])) & 0xffffffff
            
            ''' Step 4: Compute the i-th intermediate hash value.
            '''
            a0 = (a0 + a) & 0xffffffff
            b0 = (b0 + b) & 0xffffffff
            c0 = (c0 + c) & 0xffffffff
            d0 = (d0 + d) & 0xffffffff
        
        # Resulting 128-bit message digest
        return  (a0).to_bytes(4, byteorder='little') + (b0).to_bytes(4, byteorder='little') + \
                (c0).to_bytes(4, byteorder='little') + (d0).to_bytes(4, byteorder='little')

    def hexdigest(self):
        return self.digest.hex()