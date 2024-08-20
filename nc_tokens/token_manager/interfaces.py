from abc import ABC, abstractmethod
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import rsa


class TokenEncoder(ABC):
    @abstractmethod
    def encode(self,
               payload: Dict,
               private_key: rsa.RSAPrivateKey,
               token_type: str) -> str:
        """Encodes payload using private key."""
        raise NotImplementedError


class TokenDecoder(ABC):
    @abstractmethod
    def decode(self, token: str, public_key: rsa.RSAPublicKey) -> Dict:
        """Decodes payload using public key."""
        raise NotImplementedError
