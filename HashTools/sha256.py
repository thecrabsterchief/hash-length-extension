from .utils import HASH

class CONST:
    # Initial Hash Value
    H0 = 0x6a09e667
    H1 = 0xbb67ae85
    H2 = 0x3c6ef372
    H3 = 0xa54ff53a
    H4 = 0x510e527f
    H5 = 0x9b05688c
    H6 = 0x1f83d9ab
    H7 = 0x5be0cd19

    # Magic constants value to be used for each iteration.
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Number of bits in a word
    WORD_SIZE = 32

    # The rotate right (circular right shift) operation.
    @classmethod
    def ROTR(cls, x: int, shift: int):
        res = (x >> shift) | (x << cls.WORD_SIZE - shift)
        return res & 0xffffffff
    
    # Secured-defined function
    @classmethod
    def Ch(cls, x: int, y: int, z: int):
        res = (x & y) ^ (~x & z)
        return res & 0xffffffff
    
    # Secured-defined function
    @classmethod
    def Maj(cls, x: int, y: int, z: int):
        res = (x & y) ^ (x & z) ^ (y & z)
        return res & 0xffffffff
    
    # Secured-defined function
    @classmethod
    def sigma0(cls, x: int):
        res = cls.ROTR(x=x, shift=7) ^ cls.ROTR(x=x, shift=18) ^ (x >> 3)
        return res & 0xffffffff

    # Secured-defined function
    @classmethod
    def sigma1(cls, x: int):
        res = cls.ROTR(x=x, shift=17) ^ cls.ROTR(x=x, shift=19) ^ (x >> 10)
        return res & 0xffffffff

    # Secured-defined function
    @classmethod
    def SIGMA0(cls, x: int):
        res = cls.ROTR(x=x, shift=2) ^ cls.ROTR(x=x, shift=13) ^ cls.ROTR(x=x, shift=22)
        return res & 0xffffffff

    # Secured-defined function
    @classmethod
    def SIGMA1(cls, x: int):
        res = cls.ROTR(x=x, shift=6) ^ cls.ROTR(x=x, shift=11) ^ cls.ROTR(x=x, shift=25)
        return res & 0xffffffff
    

class SHA256(HASH):
    def __init__(self, message=b"") -> None:
        super().__init__(message=message, block_size=64)        
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
                `sha256(secret || original_data) = signature`  (1)
        
        :param `secret_length`: len(secret).
        :param `original_data`: the original data.
        :param `append_data`  : what ever you want.
        :param `signature`    : the value satisfies (1)
        :return: the tuple value `(new_data, new_digest)` that satisfies:
                `sha256(secret || new_data) = new_digest`
            where `new_data = original_data || padding || append_data`.
        """
        
        assert isinstance(secret_length, int) and secret_length >= 0, \
            "What did you mean a negative (or non-integer) length?"
        
        assert isinstance(signature, str) and len(signature) == 64, \
            "Make sure you have a correct SHA256 signature: 256 bits in hex"
        
        signature = bytes.fromhex(signature)
        old_padded = self._padding(
            message = bytes(secret_length) + original_data
        )

        last_blocks = self._padding(
            message = bytes(secret_length) + original_data + \
                        old_padded[secret_length + len(original_data) : ] + append_data
        )[len(old_padded):]

        init_block = [
            int.from_bytes(signature[i : i + 4], byteorder='big') for i in range(0, len(signature), 4)
        ]

        new_digest = self.__hashing(init_block=init_block, last_blocks=last_blocks)
        new_data   = original_data + old_padded[secret_length + len(original_data):] + append_data

        return new_data, new_digest.hex()

    def __hashing(self, init_block=None, last_blocks=None):
        # setup parameter if we use length extension attack
        if last_blocks and init_block:
            # preprocessing
            blocks  = self._parsing(last_blocks)

            # Setting Initial Hash Value
            h0, h1, h2, h3, h4, h5, h6, h7 = init_block
        else:
            # preprocessing
            padded_message = self._padding(self.original_message)   # padding
            blocks         = self._parsing(padded_message)          # parsing
            
            # Setting Initial Hash Value
            h0, h1, h2, h3, h4, h5, h6, h7 = [
                CONST.H0, CONST.H1, CONST.H2, CONST.H3, 
                CONST.H4, CONST.H5, CONST.H6, CONST.H7
            ]

        # SHA-256 Hashing Algorithm
        for message_block in blocks:
            
            ''' Step 1: Prepare the message shedule.
            '''
            W = []
            for t in range(64):
                if t <= 15:
                    W.append(bytes(message_block[4*t: 4*(t + 1)]))

                else:
                    term1 = CONST.sigma1(int.from_bytes(W[t - 2] , byteorder='big'))
                    term2 =              int.from_bytes(W[t - 7] , byteorder='big')
                    term3 = CONST.sigma0(int.from_bytes(W[t - 15], byteorder='big'))
                    term4 =              int.from_bytes(W[t - 16], byteorder='big')

                    schedule = (
                        (term1 + term2 + term3 + term4) & 0xffffffff
                    ).to_bytes(length=4, byteorder='big')
                    W.append(schedule)
            assert len(W) == 64

            ''' Step 2: Initialize the eight working variables with the   
                    (i-1)-st hash value.
            '''
            a, b, c, d, e, f, g, h = [
                h0, h1, h2, h3, h4, h5, h6, h7
            ]

            ''' Step 3: Iterate for t=0 to 63.
            '''
            for t in range(64):
                T1 = h + CONST.SIGMA1(e) + CONST.Ch(e, f, g) + CONST.K[t] + \
                            int.from_bytes(W[t], byteorder='big')
                T2 = CONST.SIGMA0(a) + CONST.Maj(a, b, c)

                h = g
                g = f
                f = e
                e = (d + T1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (T1 + T2) & 0xffffffff
            
            ''' Step 4: Compute the i-th intermediate hash value H(i).
            '''
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
            h4 = (h4 + e) & 0xffffffff
            h5 = (h5 + f) & 0xffffffff
            h6 = (h6 + g) & 0xffffffff
            h7 = (h7 + h) & 0xffffffff
        
        # Resulting 256-bit message digest
        return  (h0).to_bytes(4, byteorder='big') + (h1).to_bytes(4, byteorder='big') + \
                (h2).to_bytes(4, byteorder='big') + (h3).to_bytes(4, byteorder='big') + \
                (h4).to_bytes(4, byteorder='big') + (h5).to_bytes(4, byteorder='big') + \
                (h6).to_bytes(4, byteorder='big') + (h7).to_bytes(4, byteorder='big')