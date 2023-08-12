# HashTools

This is a pure python project implementing hash length extension attack. It also supports the implementation of some popular hashing algorithms.

## Currently Supported Algorithms

| Algorithm | Implementation     |  Length Extension Attack |
| :-------: | :----------------: | :----------------------: |
| MD5       | :white_check_mark: | :white_check_mark:       |
| SHA1      | :white_check_mark: | :white_check_mark:       |
| SHA224    | :white_check_mark: | :x:                      |
| SHA256    | :white_check_mark: | :white_check_mark:       |
| SHA384    | :white_check_mark: | :x:                      |
| SHA512    | :white_check_mark: | :white_check_mark:       |

## Installation

```shell
pip install HashTools
```

## Usage

### Using algorithm normally

Using `update` method (like [python hashlib](https://docs.python.org/3/library/hashlib.html))

```python
import HashTools

magic = HashTools.new(algorithm="sha256")
magic.update(b"Hello World!")
print(magic.hexdigest())
```

or just one line

```python
import HashTools

msg = b"Hello World!"
print(HashTools.new(algorithm="sha256", raw=msg).hexdigest())
```

### Using hash length extension attack

Using `extension` method

```python
import HashTools
from os import urandom

# setup context
secret = urandom(16)        # idk ¯\_(ツ)_/¯
original_data = b"&admin=False"
sig = HashTools.new(algorithm="sha256", raw=secret+original_data).hexdigest()

# attack
append_data = b"&admin=True"
magic = HashTools.new("sha256")
new_data, new_sig = magic.extension(
    secret_length=16, original_data=original_data,
    append_data=append_data, signature=sig
)
```

## Testing

- Compare my implementation with [python hashlib](https://docs.python.org/3/library/hashlib.html)

```python
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
        
        if test1 != test2:
            print(f"[!] {alg.ljust(6)} failed the validation test!")
            print(test1)
            print(test2)
            exit(1)
        else:
            print(f"[+] {alg.ljust(6)} passed the validation test!")

    print("> All test passed!!!")
```

- Testing length extension attack

```python
def test_attack():
    algorithms = [
        "md5", "sha1", "sha256", "sha512"
    ]

    print("> Implementation test...")
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

        if new_sig != HashTools.new(algorithm=alg, raw=secret + new_data).hexdigest():
            print(f"[!] Our attack didn't work with {alg.ljust(6)}")
            exit(1)
        else:
            print(f"[+] {alg.ljust(6)} passed")

    print("> All test passed!!!")
```

## License

- [MIT License](./License)

## References

- Pub, F. I. P. S. (2012). Secure hash standard (shs). Fips pub, 180(4).