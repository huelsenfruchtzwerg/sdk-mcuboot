"""
ECDSA-PKCS11 key management
"""

# SPDX-License-Identifier: Apache-2.0

import subprocess
from .general import KeyClass
from .ecdsa import ECDSA256P1Public

class PKCS11(ECDSA256P1Public):
    """
    Wrapper around an PKCS11-ECDSA private key.
    """
    def __init__(self, url, key):
        """key should be an PKCS11-URL"""
        self.key = key
        self.url = url
        self.pad_sig = False

    @staticmethod
    def generate():
        self._unsupported("generate")

    def _get_public(self):
        return self.key.key

    def raw_sign(self, payload):
        """Return the actual signature"""
        out = subprocess.run(["openssl", "dgst", "-engine", "pkcs11", "-keyform", "engine", "-sha256", "-sign", self.url, "-binary"], capture_output=True, input=payload, check=True)
        return out.stdout

    def sign(self, payload):
        sig = self.raw_sign(payload)
        if self.pad_sig:
            # To make fixed length, pad with one or two zeros.
            sig += b'\000' * (self.sig_len() - len(sig))
            return sig
        else:
            return sig
