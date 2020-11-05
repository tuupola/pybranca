# Copyright (c) 2018-2019 Mika Tuupola
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

# These are the tests each implementation should have.

def test_should_have_hello_world_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "870S4BYjk7NvyViEjUNsTEmGXbARAX9PamXZg0b3JyeIdGyZkFJhNsOQW6m0K9KnXt3ZUBqDB6hF4"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 0

def test_should_have_hello_world_with_max_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "89i7YCwtsSiYfXvOKlgkCyElnGCOEYG7zLCjUp4MuDIZGbkKJgt79Sts9RdW2Yo4imonXsILmqtNb"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 4294967295

def test_should_have_hello_world_with_nov27_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "875GH234UdXU6PkYq8g7tIM80XapDQOH72bU48YJ7SK1iHiLkrqT8Mly7P59TebOxCyQeqpMJ0a7a"

    assert branca.decode(token) == b"Hello world!"
    assert branca.timestamp(token) == 123206400

def test_should_have_eight_nul_bytes_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jIBheHWEwYIP59Wpm4QkjkIKuhc12NcYdp9Y60B6av7sZc3vJ5wBwmKJyQzGfJCrvuBgGnf"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 0

def test_should_have_eight_nul_bytes_with_max_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jrx6DUq9HmXvYdmhWMhXzx3klRzhlAjsc3tUFxDPCvZZLm16GYOzsBG4KwF1djjW1yTeZ2B"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 4294967295

def test_should_have_eight_nul_bytes_with_nov27_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jJDJOEfuc4uBJh5ivaadjo6UaBZJDZ1NsWixVCz2mXw3824JRDQZIgflRqCNKz6yC7a0JKC"

    assert branca.decode(token) == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert branca.timestamp(token) == 123206400

def test_should_throw_with_wrong_version():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "89mvl3RkwXjpEj5WMxK7GUDEHEeeeZtwjMIOogTthvr44qBfYtQSIZH5MHOTC0GzoutDIeoPVZk3w"

    # Above token has version 0xBB.
    with pytest.raises(RuntimeError):
        branca.decode(token)

def test_should_handle_empty_payload():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = branca.encode(b"")
    assert branca.decode(token) == b""

# These are the PythonHP implementation specific tests.

def test_create_token_with_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = branca.encode("Hello world!", timestamp=123206400)

    assert token == "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"

def test_create_token_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = branca.encode("Hello world!", timestamp=0)

    assert token == "870S4BYX9BNSPU3Zy4DPI4MLAK67vYRwLkocJV3DlQdwxBA0ex3fwVt5lTY3viltGFdyMA1E6E3Co"

def test_should_throw_with_wrong_version():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = "89mvl3RZe7RwH2x4azVg5V2B7X2NtG4V2YLxHAB3oFc6gyeICmCKAOCQ7Y0n08klY33eQWACd7cSZ"

    with pytest.raises(RuntimeError):
        branca.decode(token)

def test_should_throw_when_expired():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = branca.encode(b"Hello world!", timestamp=123206400)

    with pytest.raises(RuntimeError):
        branca.decode(token, 3600)

def test_encode_and_decode():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = branca.encode("Hello world!")
    decoded = branca.decode(token)

    assert decoded == b"Hello world!"

def test_encode_with_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = branca.encode("Hello world!", timestamp=123206400)
    binary = base62.decodebytes(token)
    version, timestamp = struct.unpack(">BL", bytes(binary[0:5]))

    assert version == 0xba
    assert timestamp == 123206400

def test_encode_with_zero_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = branca.encode("Hello world!", timestamp=0)
    binary = base62.decodebytes(token)
    version, timestamp = struct.unpack(">BL", bytes(binary[0:5]))

    assert version == 0xba
    assert timestamp == 0

def test_should_throw_with_invalid_token():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = branca.encode("Hello world!")

    with pytest.raises(RuntimeError):
        decoded = branca.decode("XX" + token + "XX")

def test_should_get_timestamp():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = "1jJDJOEeG2FutA8g7NAOHK4Mh5RIE8jtbXd63uYbrFDSR06dtQl9o2gZYhBa36nZHXVfiGFz"

    assert branca.timestamp(token) == 123206400