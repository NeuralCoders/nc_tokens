from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyLoader(ABC):
    """Key pair generator interface."""

    def load_keys(self) -> Tuple[Any, Any]:
        """Loads RSAPrivateKey and RSAPublicKey"""
        raise NotImplementedError
