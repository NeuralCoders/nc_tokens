from abc import ABC, abstractmethod
from typing import Optional, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyManagementGenerator(ABC):

    @abstractmethod
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
        raise NotImplementedError

    @abstractmethod
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
        raise NotImplementedError
