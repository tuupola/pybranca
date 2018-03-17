#  Branca Tokens for Python

Authenticated and encrypted API tokens using modern crypto.

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