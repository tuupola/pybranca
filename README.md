#  Branca Tokens for Python

Authenticated and encrypted API tokens using modern crypto.

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/tuupola/branca-python/master.svg?style=flat-square)](https://travis-ci.org/tuupola/branca-python)[![Coverage](https://img.shields.io/codecov/c/github/tuupola/branca-python.svg?style=flat-square)](https://codecov.io/github/tuupola/branca-python)

## Usage

```python
import json
from branca import Branca

branca = Branca(key="supersecretkeyyoushouldnotcommit")

string = json.dumps({
    "user" : "someone@example.com",
    "scope" : ["read", "write", "delete"]
})

token = branca.encode(string)
payload = branca.decode(token)
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.