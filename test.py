import HashTools
import hashlib

from typing import Union
from os import urandom
from random import randint

algorithms = [
    "sha1", "sha224", "sha256", "sha384", "sha512"
]

def new(algorithm: str):
    obj = {
        'sha1'    : HashTools.SHA1  ,
        'sha224'  : HashTools.SHA224,
        'sha256'  : HashTools.SHA256,
        'sha384'  : HashTools.SHA384,
        'sha512'  : HashTools.SHA512
    }[algorithm]()

    return obj

def test():
    for alg in algorithms:
        msg = urandom(randint(0, 1024))

        py_hash = hashlib.new(alg)
        my_hash = new(alg)

        py_hash.update(msg)
        my_hash.update(msg)

        test1 = py_hash.hexdigest()
        test2 = my_hash.hexdigest()
        
        if not test1 == test2:
            print(f"Algorithm {alg} failed the validation test!")
            exit()
    
    print("All test passed!!!")

if __name__ == "__main__":
    test()