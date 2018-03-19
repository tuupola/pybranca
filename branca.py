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

"""
Branca

Authenticated and encrypted API tokens using modern crypto.
"""

import base62
import calendar
import ctypes
import binascii
import struct
from datetime import datetime
from xchacha20poly1305 import generate_nonce
from xchacha20poly1305 import crypto_aead_xchacha20poly1305_ietf_encrypt
from xchacha20poly1305 import crypto_aead_xchacha20poly1305_ietf_decrypt
from xchacha20poly1305 import CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES
from xchacha20poly1305 import CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES

class Branca:
    VERSION = 0xBA

    def __init__(self, key):
        if isinstance(key, bytes):
            self._key = key
        else:
            self._key = key.encode()

        if len(key) is not CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES:
            raise ValueError(
                "Secrect key should be {} bytes long".format(
                    CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES
                )
            )

        self._nonce = None # Used only for unit testing!

    def encode(self, payload, timestamp=None):

        if not isinstance(payload, bytes):
            payload = payload.encode()

        if timestamp is None:
            timestamp = calendar.timegm(datetime.utcnow().timetuple())

        version = struct.pack("B", self.VERSION)
        time = struct.pack(">L", timestamp)

        if self._nonce is None:
            nonce = generate_nonce()
        else:
            nonce = self._nonce

        header = version + time + nonce
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(payload, header, nonce, self._key)

        return base62.encodebytes(header + ciphertext)

    def decode(self, token, ttl=None):
        token = base62.decodebytes(token)
        header = token[0:CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES + 5]
        nonce = header[5:CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES + 5]
        ciphertext = token[CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES + 5:]

        version, time = struct.unpack(">BL", bytes(header[0:5]))

        if ttl is not None:
            future = time + ttl
            timestamp = calendar.timegm(datetime.utcnow().timetuple())
            if future < timestamp:
                raise RuntimeError("Token is expired")


        payload = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, header, nonce, self._key)

        return payload.decode()
