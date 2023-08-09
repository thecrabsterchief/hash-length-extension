from .md5    import MD5
from .sha1   import SHA1
from .sha224 import SHA224
from .sha256 import SHA256
from .sha384 import SHA384
from .sha512 import SHA512

from typing import Union

__version__ = "0.0.1"

def new(algorithm, raw=b"") -> Union[
        MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    ]:
    obj = {
        "md5"    :  MD5,
        "sha1"   :  SHA1,
        "sha224" :  SHA224,
        "sha256" :  SHA256,
        "sha384" :  SHA384,
        "sha512" :  SHA512
    }[algorithm](raw)

    return obj

__all__ = ("new", )
