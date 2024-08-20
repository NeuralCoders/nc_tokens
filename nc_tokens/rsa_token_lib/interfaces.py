from abc import ABC
from typing import Tuple, Any


class KeyLoader(ABC):
    """Key pair generator interface."""

    def load_keys(self) -> Tuple[Any, Any]:
        """Loads RSAPrivateKey and RSAPublicKey"""
        raise NotImplementedError
