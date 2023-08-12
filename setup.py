from setuptools import setup, find_packages

with open("./README.md", "r") as f:
    long_desc = f.read()

classifiers = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Education',
    'Topic :: Security',
    'Topic :: Security :: Cryptography',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3'
]

setup(
    name="length-extension-tool",
    version="0.1.0",
    license="MIT",
    description="A pure python tool to implement/exploit the hash length extension attack",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="Nguyen Chuong Vo",
    author_email="viensea1106@gmail.com",
    url="https://github.com/viensea1106/hash-length-extension",
    keywords=["hash length extension", "md5", "sha1", "sha224", "sha256", "sha512"],
    classifiers=classifiers,
    packages=find_packages()
)