import os
from dataclasses import dataclass
from typing import Optional, Dict, Tuple, Any
from src.rsa_token_lib import (RSAKeyPairGenerator, JWTEncoder, JWTDecoder,
                               PEMKeySerializer, FileKeyPersistence)
from ..token_manager import KeyManagement, TokenManager
from .interfaces import ExecutionContainerCreator


@dataclass
class AppConfig:
    private_key_path: str = 'src/keys/private_key.pem'
    public_key_path: str = 'src/keys/public_key.pem'
    key_password: bytes = b'testing'


class Authenticator:

    @staticmethod
    def authenticate(username: str, password: str) -> Optional[Dict]:
        if username == "user" and password == "password":
            return {"user_id": 123, "username": username}
        return None


class ExecutionContainer(ExecutionContainerCreator):
    def __init__(self, config: AppConfig):
        self.config = config
        self.encoder = JWTEncoder()
        self.decoder = JWTDecoder()
        self.authenticator = Authenticator()
        self.key_serializer = PEMKeySerializer()
        self.key_persistence = FileKeyPersistence()
        self.key_generator = RSAKeyPairGenerator()
        self.key_manager = self._create_key_manager()
        self.token_manager = self._create_token_manager()

    def _create_key_manager(self):
        return KeyManagement(
            key_generator=self.key_generator,
            key_persistence=self.key_persistence,
            key_serializer=self.key_serializer
        )

    def _create_token_manager(self):
        return TokenManager(
            self,
            self.encoder,
            self.decoder,
            self.authenticator
        )

    def initialize_keys(self) -> None:
        if not self._keys_exist():
            print("Keys do not exist. Generating new keys...")
            self.key_manager.generate_and_save_keys(
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
            raise FileNotFoundError(
                "Keys do not exist. Please run initialize_keys() first."
            )
        return self.key_manager.load_keys(
            self.config.private_key_path,
            self.config.public_key_path,
            self.config.key_password
        )

    def create_token(self, username: str, password: str) -> Optional[str]:
        return self.token_manager.create_token(username, password)


def initialize_library():
    config = AppConfig()
    container = ExecutionContainer(config)
    container.initialize_keys()
    print("Library initialized successfully.")
