from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ..rsa_token_lib import KeySerializer, KeyPairGenerator, KeyPersistence


class KeyManagement:
    def __init__(
            self,
            key_generator: KeyPairGenerator,
            key_serializer: KeySerializer,
            key_persistence: KeyPersistence
    ) -> None:
        self._key_generator = key_generator
        self._key_serializer = key_serializer
        self._key_persistence = key_persistence

    def generate_and_save_keys(
            self,
            private_key_file: str,
            public_key_file: str,
            password: bytes
    ) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generates and saves private and public keys in the directory
        :param private_key_file: file folder in which to save private keys
        :param public_key_file: file folder in which to save public keys
        :param password: password in bytes to save the private and public keys
        :return: private key and public key tuple
        """
        private_key, public_key = self._key_generator.generate_keys()
        private_key_bytes = self._key_serializer.serialize_private_key(
            private_key,
            password
        )
        public_key_bytes = self._key_serializer.serialize_public_key(
            public_key
        )
        self._key_persistence.save_key(private_key_bytes, private_key_file)
        self._key_persistence.save_key(public_key_bytes, public_key_file)
        return private_key, public_key

    def load_keys(
            self,
            private_key_file: str,
            public_key_file: str,
            password: bytes
    ) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Loads private and public keys from the directory
        :param private_key_file: file folder in which to load from private keys
        :param public_key_file: file folder in which to load from public keys
        :param password: password in bytes to load the private and public keys
        :return: private and public key tuple
        """
        private_key_bytes = self._key_persistence.load_key(private_key_file)
        public_key_bytes = self._key_persistence.load_key(public_key_file)
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password,
            default_backend()
        )
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            default_backend()
        )
        return private_key, public_key
