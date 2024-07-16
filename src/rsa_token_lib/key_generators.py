from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import Tuple


class RSAKeyPairGenerator:
    """
    Generates RSA key pairs.
    """

    def __init__(self, public_exponent: int = 65537, key_size: int = 2048):
        self.public_exponent = public_exponent
        self.key_size = key_size

    def generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generates a new RSA key pair with a specified public exponent.
        :return: private key and public key
        """

        private_key = rsa.generate_private_key(
            public_exponent=self.public_exponent,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
