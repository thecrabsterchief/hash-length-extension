from .utils import HASH

class CONST:
    # Initial Hash Value
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    # Magic constants value to be used for each iteration.
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

    # Number of bits in a word
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

    # length extension attack
    def extension(self, 
            secret_length: int, original_data: bytes, 
            append_data: bytes, signature: str
        ):
        """ Length Extension Attack. Compute message digest without knowing 
            the `secret` value:
                `md5(secret || original_data) = signature`  (1)
        
        :param `secret_length`: len(secret).
        :param `original_data`: the original data.
        :param `append_data`  : what ever you want.
        :param `signature`    : the value satisfies (1)
        :return: the tuple value `(new_data, new_digest)` that satisfies:
                `md5(secret || new_data) = new_digest`
            where `new_data = original_data || padding || append_data`.
        """
        
        assert isinstance(secret_length, int) and secret_length >= 0, \
            "What did you mean a negative (or non-integer) length?"
        
        assert isinstance(signature, str) and len(signature) == 32, \
            "Make sure you have a correct MD5 signature: 128 bits in hex"
        
        signature = bytes.fromhex(signature)
        old_padded = self._padding(
            message = bytes(secret_length) + original_data
        )

        last_blocks = self._padding(
            message = bytes(secret_length) + original_data + \
                        old_padded[secret_length + len(original_data) : ] + append_data
        )[len(old_padded):]

        init_block = [
            int.from_bytes(signature[i : i + 4], byteorder='little') for i in range(0, len(signature), 4)
        ]

        new_digest = self.__hashing(init_block=init_block, last_blocks=last_blocks)
        new_data   = original_data + old_padded[secret_length + len(original_data):] + append_data

        return new_data, new_digest.hex()

    # md5 use little endian
    def _padding(self, message):
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
    
    def __hashing(self, init_block=None, last_blocks=None):
        # setup parameter if we use length extension attack
        if last_blocks and init_block:
            # preprocessing
            blocks  = self._parsing(last_blocks)

            # Setting Initial Hash Value
            a0, b0, c0, d0 = init_block
            
        else:
            # preprocessing
            padded_message = self._padding(self.original_message)   # padding
            blocks         = self._parsing(padded_message)          # parsing
            
            # Setting Initial Hash Value
            a0, b0, c0, d0 = [CONST.A, CONST.B, CONST.C, CONST.D]


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