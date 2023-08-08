# Parent class for hash functions

class HASH:
    def __init__(self, message, block_size) -> None:
        self.BLOCK_SIZE = block_size

        if isinstance(message, str):
            self.original_message = message.encode("ascii")
        elif isinstance(message, bytes):
            self.original_message = message
        else:
            raise TypeError

    def _update(self, message):
        self.original_message += message
    
    def _preprocessing(self):
        # Get current message

        message = self.original_message

        # Padding the Message

        bit_length = len(message) * 8
        message += b"\x80" 
        while (len(message) * 8 + self.BLOCK_SIZE) % (self.BLOCK_SIZE * 8):
            message += b"\x00"
        
        message += bit_length.to_bytes(
            length=self.BLOCK_SIZE//8, byteorder='big'
        )

        assert len(message) % self.BLOCK_SIZE == 0, \
                "Something goes wrong when padding!"

        # Parsing the Message

        self.blocks = []
        for i in range(0, len(message), self.BLOCK_SIZE):
            self.blocks.append(message[i : i + self.BLOCK_SIZE])
        
    def _hashing(self):
        pass