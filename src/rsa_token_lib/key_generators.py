from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple
from .interfaces import KeyPairGenerator, KeySerializer


class RSAKeyPairGenerator(KeyPairGenerator):
    """Generates RSA key pairs."""

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


class PEMKeySerializer(KeySerializer):
    """Serializes RSA key pairs to PEM format."""
    @staticmethod
    def serialize_private_key(
            private_key: rsa.RSAPrivateKey,
            password: bytes
    ) -> bytes:
        """
        Serializes a private key into a PEM format.
        :param private_key: private key
        :param password: password
        :return:
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password
            )
        )

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """
        Serializes a public key into a PEM format.
        :param public_key: public key
        :return:
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
