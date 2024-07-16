from abc import ABC, abstractmethod
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPairGenerator(ABC):
    """Key pair generator interface."""

    @abstractmethod
    def generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates RSAPrivateKey and RSAPublicKey function"""
        raise NotImplementedError
