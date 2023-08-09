from .utils import HASH

class CONST:
    # Initial Hash Value
    H0 = 0x67452301
    H1 = 0xEFCDAB89
    H2 = 0x98BADCFE
    H3 = 0x10325476
    H4 = 0xC3D2E1F0

    # Magic constants value to be used for each iteration.
    K = [
        0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
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
    def Ch(cls, x: int, y: int, z: int):
        res =  (x & y) ^ (~x & z)
        return res & 0xffffffff
    
    # Secured-defined function
    @classmethod
    def Parity(cls, x: int, y: int, z: int):
        res =  x ^ y ^ z
        return res & 0xffffffff
    
    # Secured-defined function
    @classmethod
    def Maj(cls, x: int, y: int, z: int):
        res =  (x & y) ^ (x & z) ^ (y & z)
        return res & 0xffffffff


class SHA1(HASH):
    def __init__(self, message=b"") -> None:
        super().__init__(message=message, block_size=64)        
        self.__digest = self._hashing()

    def update(self, message=b""):
        super()._update(message=message)
        self.__digest = self._hashing()

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
                `sha1(secret || original_data) = signature`  (1)
        
        :param `secret_length`: len(secret).
        :param `original_data`: the original data.
        :param `append_data`  : what ever you want.
        :param `signature`    : the value satisfies (1)
        :return: the tuple value `(new_data, new_digest)` that satisfies:
                `sha1(secret || new_data) = new_digest`
            where `new_data = original_data || padding || append_data`.
        """
        
        assert isinstance(secret_length, int) and secret_length >= 0, \
            "What did you mean a negative (or non-integer) length?"
        
        assert isinstance(signature, str) and len(signature) == 40, \
            "Make sure you have a correct SHA1 signature: 160 bits in hex"
        
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

        new_digest = self._hashing(init_block=init_block, last_blocks=last_blocks)
        new_data   = original_data + old_padded[secret_length + len(original_data):] + append_data

        return new_data, new_digest.hex()

    def _hashing(self, init_block=None, last_blocks=None):
        # setup parameter if we use length extension attack
        if last_blocks and init_block:
            # preprocessing
            blocks  = self._parsing(last_blocks)

            # Setting Initial Hash Value
            h0, h1, h2, h3, h4 = init_block
        else:
            # preprocessing
            padded_message = self._padding(self.original_message)   # padding
            blocks         = self._parsing(padded_message)          # parsing
            
            # Setting Initial Hash Value
            h0, h1, h2, h3, h4 = [CONST.H0, CONST.H1, CONST.H2, CONST.H3, CONST.H4]

        # SHA-1 Hashing Algorithm
        for message_block in blocks:
            
            ''' Step 1: Prepare the message shedule.
            '''
            W = []
            for t in range(80):
                if t <= 15:
                    W.append(bytes(message_block[4*t: 4*(t + 1)]))

                else:
                    term1 = int.from_bytes(W[t - 3 ] , byteorder='big')
                    term2 = int.from_bytes(W[t - 8 ] , byteorder='big')
                    term3 = int.from_bytes(W[t - 14] , byteorder='big')
                    term4 = int.from_bytes(W[t - 16] , byteorder='big')


                    schedule = (
                        CONST.ROTL(x=term1 ^ term2 ^ term3 ^ term4, shift=1)
                    ).to_bytes(length=4, byteorder='big')
                    W.append(schedule)

            assert len(W) == 80

            ''' Step 2: Initialize the eight working variables with the   
                    (i-1)-st hash value.
            '''
            a, b, c, d, e = [
                h0, h1, h2, h3, h4
            ]

            ''' Step 3: Iterate for t=0 to 79.
            '''
            for t in range(80):
                # T = ROTL(a, 5) + f(b,c,d) + e + Kt + Wt
                if t <= 19:
                    f = CONST.Ch(b, c, d)
                    K = CONST.K[0]
                
                elif t <= 39:
                    f = CONST.Parity(b, c, d)
                    K = CONST.K[1]

                elif t <= 59:
                    f = CONST.Maj(b, c, d   )
                    K = CONST.K[2]
                
                else:
                    f = CONST.Parity(b, c, d)
                    K = CONST.K[3]
            
                T =  CONST.ROTL(x=a, shift=5) + f + e + K + int.from_bytes(W[t], byteorder='big')
                e = d
                d = c
                c = CONST.ROTL(x=b, shift=30)
                b = a
                a = T & 0xffffffff

            ''' Step 4: Compute the i-th intermediate hash value H(i).
            '''
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
            h4 = (h4 + e) & 0xffffffff
        
        # Resulting 160-bit message digest
        return  (h0).to_bytes(4, byteorder='big') + (h1).to_bytes(4, byteorder='big') + \
                (h2).to_bytes(4, byteorder='big') + (h3).to_bytes(4, byteorder='big') + \
                (h4).to_bytes(4, byteorder='big') 