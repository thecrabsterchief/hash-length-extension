from .sha1   import SHA1
from .sha224 import SHA224
from .sha256 import SHA256
from .sha384 import SHA384
from .sha512 import SHA512

__version__ = "0.0.1"

def new(algorithm):
    obj = {
        "sha1"   :  SHA1,
        "sha224" :  SHA224,
        "sha256" :  SHA256,
        "sha384" :  SHA384,
        "sha512" :  SHA512
    }[algorithm]()

    return obj

__all__ = ("new", ) 
