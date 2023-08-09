import HashTools
import hashlib

from os import urandom
from random import randint

algorithms = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512"
]

def test():
    for alg in algorithms:
        msg = urandom(randint(0, 1024))

        py_hash = hashlib.new(alg)
        my_hash = HashTools.new(alg)

        py_hash.update(msg)
        my_hash.update(msg)

        test1 = py_hash.hexdigest()
        test2 = my_hash.hexdigest()
        
        if test1 != test2:
            print(f"Algorithm {alg} failed the validation test!")
            print(test1)
            print(test2)
            exit()
    
    print("All test passed!!!")

if __name__ == "__main__":
    test()