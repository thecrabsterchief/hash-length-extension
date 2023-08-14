import HashTools
import hashlib

from os import urandom
from random import randint

def test_imple():
    algorithms = [
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512"
    ]

    print("> Implementation test...")
    for alg in algorithms:
        msg = urandom(randint(0, 1024))

        py_hash = hashlib.new(alg)
        my_hash = HashTools.new(alg)

        py_hash.update(msg)
        my_hash.update(msg)

        test1 = py_hash.hexdigest()
        test2 = my_hash.hexdigest()
        
        assert test1 == test2, \
            f"[!] {alg.ljust(6)} failed the validation test!"

    print("> All test passed!!!")

def test_attack():
    algorithms = [
        "md5", "sha1", "sha256", "sha512"
    ]

    print("> Length extension test...")
    for alg in algorithms:
        # setup context
        length = randint(0, 1024)           
        secret = urandom(length)            # idk ¯\_(ツ)_/¯
        original_data = b"admin=False"
        sig = HashTools.new(algorithm=alg, raw=secret + original_data).hexdigest()
        
        # attack
        append_data = b"admin=True;"
        magic = HashTools.new(alg)
        new_data, new_sig = magic.extension(
            secret_length=length, original_data=original_data,
            append_data=append_data, signature=sig
        )

        assert new_sig == HashTools.new(algorithm=alg, raw=secret + new_data).hexdigest(), \
            f"[!] Our attack didn't work with {alg.ljust(6)}"

    print("> All test passed!!!")