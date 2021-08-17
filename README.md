#  Branca Tokens for Python

Authenticated and encrypted API tokens using modern crypto.


[![Latest Version](https://img.shields.io/pypi/v/pybranca.svg?style=flat-square)](https://pypi.org/project/pybranca/)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/github/workflow/status/tuupola/pybranca/Tests/master?style=flat-square)](https://github.com/tuupola/pybranca/actions)
[![Coverage](https://img.shields.io/codecov/c/github/tuupola/pybranca.svg?style=flat-square)](https://codecov.io/github/tuupola/pybranca)

## What?

[Branca](https://github.com/tuupola/branca-spec/) is a secure easy to use token format which makes it hard to shoot yourself in the foot. It uses IETF XChaCha20-Poly1305 AEAD symmetric encryption to create encrypted and tamperproof tokens. Payload itself is an arbitrary sequence of bytes. You can use for example a JSON object, plain text string or even binary data serialized by [MessagePack](http://msgpack.org/) or [Protocol Buffers](https://developers.google.com/protocol-buffers/).

Although not a design goal, it is possible to use [Branca as an alternative to JWT](https://appelsiini.net/2017/branca-alternative-to-jwt/).

## Install

Install the library using pip. Note that you also must have [libsodium](https://download.libsodium.org/doc/) installed.

```
$ brew install libsodium
$ pip install pybranca
```

## Usage

The payload of the token can be anything, like a simple string.

```python
import secrets
from branca import Branca

key = secrets.token_bytes(32)
branca = Branca(key)

token = branca.encode("Hello world!")
payload = branca.decode(token)

print(token)
print(payload)

# 87xqn4ACMhqDZvoNuO0pXykuDlCwRz4Vg7LS3klfHpTiOUw1ramOqfWoaA6bvsGwOQ49MDFOERU0T
# b'Hello world!'
```

For more complicated data structures JSON is an usual choice.

```python
import json
import secrets
from branca import Branca

key = secrets.token_bytes(32)
branca = Branca(key)

string = json.dumps({"scope" : ["read", "write", "delete"]})

token = branca.encode(string)
payload = branca.decode(token)

print(token)
print(payload)
print(json.loads(payload))

# 6AlLJaBIFpXbwKTFsI3xXsk4se8YsdEKOtxYwtYDQHpoqabwZzmxAUS99BLxBJpmfJqnJ9VvzJYO1FXfsX78d0YsvTe43opYbUPgUao0EGV5qBli
# b'{"scope": ["read", "write", "delete"]}'
# {'scope': ['read', 'write', 'delete']}
```

By using [MessagePack](https://msgpack.org/) you can have more compact tokens.

```python
import msgpack
from branca import Branca

key = secrets.token_bytes(32)
branca = Branca(key)

packed = msgpack.dumps({"scope" : ["read", "write", "delete"]})

token = branca.encode(packed)
payload = branca.decode(token)

print(token)
print(payload)
print(msgpack.loads(payload, raw=False))

# 3iJOQqw5CWjCRRDnsd7Jh4dfsyf7a4qbuEO0uT8MBEvnMVaR8rOW4dFKBVFKKgxZkVlNchGJSIgPdHtHIM4rF4mZYsriTE37
# b'\x81\xa5scope\x93\xa4read\xa5write\xa6delete'
# {'scope': ['read', 'write', 'delete']}
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.