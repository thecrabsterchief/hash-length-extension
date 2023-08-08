from .utils import HASH

class CONST:
    # Initial Hash Value
    H0 = 0x67452301
    H1 = 0xEFCDAB89
    H2 = 0x98BADCFE
    H3 = 0x10325476
    H4 = 0xC3D2E1F0

    # Magic constants
    K = [
        0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
    ]

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
        self.digest = self._hashing()

    def update(self, message=b""):
        super()._update(message=message)
        self.digest = self._hashing()

    def _hashing(self):
        # preprocessing
        super()._preprocessing()

        # Setting Initial Hash Value
        h0, h1, h2, h3, h4 = [
            CONST.H0, CONST.H1, CONST.H2 , CONST.H3, CONST.H4
        ]

        # SHA-1 Hashing Algorithm
        for message_block in self.blocks:
            
            ''' Step 1: Prepare the message shedule.
            '''
            message_schedule = []
            for t in range(80):
                if t <= 15:
                    message_schedule.append(bytes(message_block[4*t: 4*(t + 1)]))

                else:
                    term1 = int.from_bytes(message_schedule[t - 3 ] , byteorder='big')
                    term2 = int.from_bytes(message_schedule[t - 8 ] , byteorder='big')
                    term3 = int.from_bytes(message_schedule[t - 14] , byteorder='big')
                    term4 = int.from_bytes(message_schedule[t - 16] , byteorder='big')


                    schedule = (
                        CONST.ROTL(x=term1 ^ term2 ^ term3 ^ term4, shift=1)
                    ).to_bytes(length=4, byteorder='big')
                    message_schedule.append(schedule)

            assert len(message_schedule) == 80

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
            
                T =  CONST.ROTL(x=a, shift=5) + f + e + K + int.from_bytes(message_schedule[t], byteorder='big')
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
        
        # Resulting 256-bit message digest
        return  (h0).to_bytes(4, byteorder='big') + (h1).to_bytes(4, byteorder='big') + \
                (h2).to_bytes(4, byteorder='big') + (h3).to_bytes(4, byteorder='big') + \
                (h4).to_bytes(4, byteorder='big') 

    def hexdigest(self):
        return self.digest.hex()