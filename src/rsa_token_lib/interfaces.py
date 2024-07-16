from abc import ABC, abstractmethod
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPairGenerator(ABC):
    @abstractmethod
    def generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        raise NotImplementedError
