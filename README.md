# drax_ecdh_py
Python wrapper for Drax ECDH C-library

### Installation 
To install the package you need to run the following command:

`$ python3 -m pip install --index-url https://test.pypi.org/simple/ --no-deps draxecdh`

### Usage 
Import ECDH crypto module in your code:
```python
from draxecdh import crypto

print(crypto.crypto_aesChunkSize())
```
