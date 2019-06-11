# pyHeal
This project implements Python wrappers for Homomorphic Encryption libraries, aimed at being more Python friendly.

It currently contains:
- A pybind11 based Python wrapper for [Microsoft SEAL](https://github.com/CJRChang/SEAL) in `seal_wrapper`
- A Pythonic wrapper for `seal_wrapper` in `pyheal/wrapper.py`
- A Python ciphertext type of object that allows math operations as if they were python numbers in `pyheal/ciphertext_op.py`
- A standard encoder/decoder interface for seal encoders and encryptors for use of the `CiphertextOp` objects in `pyheal/encoders.py`.
     

Tests:
- A partial re-implementation of [Microsoft SEAL's examples](https://github.com/CJRChang/SEAL) using `wrapper.py` in `tests.py`
- A large number of tests for PyHEAL and `CiphertextOp` in `pyheal/test_pyheal.py` 


# Setup
Clone using:
Git v2.13+: `git clone --recurse-submodules (repository URL)`

Git v1.6.5 - v2.12: `git clone --recursive (repository URL)`

For a repository that has already been cloned or older versions of git run:
`git submodule update --init --recursive`

## Build
This project can be built directly using `pip3`.
Optionally create and activate a new Python virtual environment using `virtualenv` first, for example:
```bash
python3 -m virtualenv ./venv --python python3

#Linux
source ./venv/bin/activate

#Windows
#venv\Scripts\activate
```

Install dependencies and package:
```bash
pip3 install .
```

# Usage
```python
import pyheal


# Set encryption params + obtain an EncryptorOp object
...
encryptor = EncryptorOp(...)
decryptor = Decryptor(...)

v1 = encryptor_encoder.encode(10)
v2 = encryptor_encoder.encode(20)

result = v1 + v2

print(decryptor.decrypt(result)) # Prints 30 after decrypt 

```
See [example_usage.py](example_usage.py) for more usage examples.
