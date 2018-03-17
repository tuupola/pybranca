# Copyright 2018 Mika Tuupola
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
import xchacha20poly1305

def test_vector1():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    branca._nonce = unhexlify("0102030405060708090a0b0c0102030405060708090a0b0c")
    token = branca.encode("Hello world!", timestamp=123206400)

    assert token == "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"

def test_encode_and_decode():
    branca = Branca(key="supersecretkeyyoushouldnotcommit")
    token = branca.encode("Hello world!")
    decoded = branca.decode(token)

    assert decoded == "Hello world!"
