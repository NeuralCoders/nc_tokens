from abc import ABC, abstractmethod
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPairGenerator(ABC):
    """Key pair generator interface."""

    @abstractmethod
    def generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates RSAPrivateKey and RSAPublicKey function"""
        raise NotImplementedError


class TokenEncoder(ABC):
    @abstractmethod
    def encode(self, payload: Dict, private_key: rsa.RSAPrivateKey) -> str:
        """Encodes payload using private key."""
        raise NotImplementedError


class TokenDecoder(ABC):
    @abstractmethod
    def decode(self, token: str, public_key: rsa.RSAPublicKey) -> Dict:
        """Decodes payload using public key."""
        raise NotImplementedError


class KeySerializer(ABC):
    @staticmethod
    @abstractmethod
    def serialize_private_key(
            private_key: rsa.RSAPrivateKey,
            password: bytes
    ) -> bytes:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        raise NotImplementedError


class KeyPersistence(ABC):

    @staticmethod
    @abstractmethod
    def save_key(key_bytes: bytes, filename: str):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def load_key(filename: str):
        raise NotImplementedError
