import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Any
from .interfaces import KeyPairGenerator, KeySerializer, KeyPersistence


@dataclass
class AppConfig:
    private_key_path: str = 'src/keys/private_key.pem'
    public_key_path: str = 'src/keys/public_key.pem'
    key_password: bytes = b'testing'


class RSAKeyPairGenerator(KeyPairGenerator):
    """Generates RSA key pairs."""

    def __init__(
            self,
            key_serializer: KeySerializer,
            key_persistence: KeyPersistence,
            public_exponent: int = 65537,
            key_size: int = 2048,
    ):
        self.public_exponent = public_exponent
        self.key_size: int = key_size
        self._key_persistence = key_persistence
        self._key_serializer = key_serializer
        self.config = AppConfig()

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

    def _initialize_keys(self) -> None:
        if not self._keys_exist():
            print("Keys do not exist. Generating new keys...")
            self.generate_and_save_keys(
                self.config.private_key_path,
                self.config.public_key_path,
                self.config.key_password
            )
        else:
            print("Keys already exist. Skipping key generation.")

    def _keys_exist(self) -> bool:
        return os.path.exists(self.config.private_key_path) and os.path.exists(
            self.config.public_key_path
        )

    def load_keys(self) -> Tuple[Any, Any]:
        if not self._keys_exist():
            self._initialize_keys()
        return self.load_and_extract_keys(
            self.config.private_key_path,
            self.config.public_key_path,
            self.config.key_password
        )

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
        private_key, public_key = self.generate_keys()
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

    def load_and_extract_keys(
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
        :return: PEM formatted private key in bytes
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
        :return: PEM formatted public key in bytes
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


class FileKeyPersistence(KeyPersistence):

    @staticmethod
    def save_key(key_bytes: bytes, filename: str) -> None:
        """
        Saves a key pair to a file.
        :param key_bytes: key in bytes
        :param filename: filename and file folder
        :return:
        """
        with open(filename, 'wb') as key_file:
            key_file.write(key_bytes)

    @staticmethod
    def load_key(filename: str) -> bytes:
        """
        Loads a key from a file.
        :param filename: filename and file folder where keys are stored
        :return: the file from a directory
        """
        with open(filename, 'rb') as key_file:
            return key_file.read()
