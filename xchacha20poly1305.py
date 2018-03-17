# Wrapper for libsodium IETF XChaCha20-Poly1305 AEAD
#
# Copyright (c) 2013-2018, Marsiske Stefan.
# Copyright (c) 2018 Mika Tuupola.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
IETF XChaCha20-Poly1305 AEAD

Wrapper for libsodium IETF XChaCha20-Poly1305 AEAD functions.
"""

import ctypes
import ctypes.util

library_path = ctypes.util.find_library("sodium") or ctypes.util.find_library("libsodium")
sodium = ctypes.cdll.LoadLibrary(library_path)

if not sodium._name:
    raise RuntimeError("Unable to locate libsodium")

CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES = sodium.crypto_aead_xchacha20poly1305_ietf_keybytes()
CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES = sodium.crypto_aead_xchacha20poly1305_ietf_npubbytes()
CRYPTO_AEAD_XHCACHA20POLY1305_IETF_ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_abytes()

# crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
#                                           MESSAGE, MESSAGE_LEN,
#                                           ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
#                                           NULL, nonce, key);

def crypto_aead_xchacha20poly1305_ietf_encrypt(message, ad, nonce, key):
    if len(nonce) is not CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES:
        raise ValueError("Invalid nonce")

    if len(key) is not CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES:
        raise ValueError("Invalid key")

    message_len = ctypes.c_ulonglong(len(message))

    if ad is None:
        ad_len = ctypes.c_ulonglong(0)
    else:
        ad_len = ctypes.c_ulonglong(len(ad))

    ciphertext = ctypes.create_string_buffer(
        message_len.value + CRYPTO_AEAD_XHCACHA20POLY1305_IETF_ABYTES
    )
    ciphertext_len = ctypes.c_ulonglong(0)

    retval = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, ctypes.byref(ciphertext_len),
        message, message_len,
        ad, ad_len,
        None, nonce, key
    )

    if retval != 0:
        raise RuntimeError("Encrypting token failed")

    return ciphertext.raw

# if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
#                                               NULL,
#                                               ciphertext, ciphertext_len,
#                                               ADDITIONAL_DATA,
#                                               ADDITIONAL_DATA_LEN,
#                                               nonce, key) != 0) {

def crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, ad, nonce, key):
    if len(nonce) != CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES:
        raise ValueError("Invalid nonce")

    if len(key) != CRYPTO_AEAD_XHCACHA20POLY1305_IETF_KEYBYTES:
        raise ValueError("Invalid key")

    decrypted = ctypes.create_string_buffer(
        len(ciphertext) - CRYPTO_AEAD_XHCACHA20POLY1305_IETF_ABYTES
    )
    decrypted_len = ctypes.c_ulonglong(0)
    ciphertext_len = ctypes.c_ulonglong(len(ciphertext))

    if ad is None:
        ad_len = ctypes.c_ulonglong(0)
    else:
        ad_len = ctypes.c_ulonglong(len(ad))

    retval = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted, ctypes.byref(decrypted_len),
        None,
        ciphertext, ciphertext_len,
        ad, ad_len,
        nonce, key
    )

    if retval != 0:
        raise RuntimeError("Decrypting token failed")

    return decrypted.raw

def generate_nonce():
    buffer = ctypes.create_string_buffer(CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES)
    sodium.randombytes(buffer, ctypes.c_ulonglong(CRYPTO_AEAD_XHCACHA20POLY1305_IETF_NPUBBYTES))
    return buffer.raw