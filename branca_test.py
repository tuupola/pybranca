# Copyright (c) 2018-2020 Mika Tuupola
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of  this software and associated documentation files (the "Software"), to
# deal in  the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copied of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from branca import Branca
from binascii import unhexlify, hexlify
import base62
import pytest
import struct
import xchacha20poly1305

#
# Decoding vectors
#

# Test vector 8
def test_decode_hello_world_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 0

# Test vector 9
def test_decode_hello_world_with_max_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 4294967295

# Test vector 10
def test_decode_hello_world_with_nov27_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 123206400

# Test vector 11
def test_decode_eight_nul_bytes_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jIBheHbDdkCDFQmtgw4RUZeQoOJgGwTFJSpwOAk3XYpJJr52DEpILLmmwYl4tjdSbbNqcF1"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 0

# Test vector 12
def test_decode_eight_nul_bytes_with_max_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jrx6DUu5q06oxykef2e2ZMyTcDRTQot9ZnwgifUtzAphGtjsxfbxXNhQyBEOGtpbkBgvIQx"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 4294967295

# Test vector 13
def test_decode_eight_nul_bytes_with_nov27_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jJDJOEjuwVb9Csz1Ypw1KBWSkr0YDpeBeJN6NzJWx1VgPLmcBhu2SbkpQ9JjZ3nfUf7Aytp"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 123206400

# Test vector 14
def test_decode_empty_payload():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"

    assert branca.decode(token) == b""
    assert branca.timestamp(token) == 0

# Test vector 15
def test_decode_non_utf8_payload():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "K9u6d0zjXp8RXNUGDyXAsB9AtPo60CD3xxQ2ulL8aQoTzXbvockRff0y1eXoHm"

    assert branca.decode(token) == b"\x80"
    assert branca.timestamp(token) == 123206400

# Test vector 16
def test_should_throw_with_wrong_version():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "89mvl3RkwXjpEj5WMxK7GUDEHEeeeZtwjMIOogTthvr44qBfYtQSIZH5MHOTC0GzoutDIeoPVZk3w"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 17
def test_should_throw_with_invalid_base62():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT_"

    with pytest.raises(ValueError):
        branca.decode(token)

# Test vector 18
def test_should_throw_with_modified_version():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "89mvl3S0BE0UCMIY94xxIux4eg1w5oXrhvCEXrDAjusSbO0Yk7AU6FjjTnbTWTqogLfNPJLzecHVb"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 19
def test_should_throw_with_modified_nonce():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "875GH233SUysT7fQ711EWd9BXpwOjB72ng3ZLnjWFrmOqVy49Bv93b78JU5331LbcY0EEzhLfpmSx"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 20
def test_should_throw_with_modified_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "870g1RCk4lW1YInhaU3TP8u2hGtfol16ettLcTOSoA0JIpjCaQRW7tQeP6dQmTvFIB2s6wL5deMXr"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 21
def test_should_throw_with_modified_ciphertext():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5Qw6Jpo96myliI3hHD7VbKZBYh"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 22
def test_should_throw_with_modified_tag():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trk0"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 23
def test_should_throw_with_wrong_key():
    branca = Branca(key="wrongsecretkeyyoushouldnotcommit")
    token = "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"

    with pytest.raises(RuntimeError):
        branca.decode(token)

# Test vector 24
def test_should_throw_with_invalid_key():
    with pytest.raises(ValueError):
        branca = Branca(key="tooshortkey")

#
# Encoding vectors
#

# Test vector 0
def test_encode_hello_world_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode("Hello world!", timestamp=0)

    assert token == "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z"

# Test vector 1
def test_encode_hello_world_with_max_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode("Hello world!", timestamp=4294967295)

    assert token == "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr"

# Test vector 2
def test_encode_hello_world_with_november_27_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode("Hello world!", timestamp=123206400)

    assert token == "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"

# Test vector 3
def test_encode_eight_nul_bytes_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"\x00\x00\x00\x00\x00\x00\x00\x00", timestamp=0)

    assert token == "1jIBheHbDdkCDFQmtgw4RUZeQoOJgGwTFJSpwOAk3XYpJJr52DEpILLmmwYl4tjdSbbNqcF1"

# Test vector 4
def test_encode_eight_nul_bytes_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"\x00\x00\x00\x00\x00\x00\x00\x00", timestamp=4294967295)

    assert token == "1jrx6DUu5q06oxykef2e2ZMyTcDRTQot9ZnwgifUtzAphGtjsxfbxXNhQyBEOGtpbkBgvIQx"

# Test vector 5
def test_encode_eight_nul_bytes_with_november_27_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"\x00\x00\x00\x00\x00\x00\x00\x00", timestamp=123206400)

    assert token == "1jJDJOEjuwVb9Csz1Ypw1KBWSkr0YDpeBeJN6NzJWx1VgPLmcBhu2SbkpQ9JjZ3nfUf7Aytp"

# Test vector 6
def test_encode_empty_payload():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"", timestamp=0)

    assert token == "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"

# Test vector 7
def test_encode_non_utf8_payload():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
    token = branca.encode(b"", timestamp=0)

    assert token == "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5"

#
# Implementation specific tests
#

def test_should_throw_when_expired():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = branca.encode(b"Hello world!", timestamp=123206400)

    with pytest.raises(RuntimeError):
        branca.decode(token, 3600)

def test_should_get_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jJDJOEeG2FutA8g7NAOHK4Mh5RIE8jtbXd63uYbrFDSR06dtQl9o2gZYhBa36nZHXVfiGFz"

    assert branca.timestamp(token) == 123206400