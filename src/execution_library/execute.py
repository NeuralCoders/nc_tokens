from typing import Optional, Dict
from src.rsa_token_lib import (RSAKeyPairGenerator, PEMKeySerializer,
                               FileKeyPersistence)
from src.token_manager import TokenManager, JWTDecoder, JWTEncoder
from .interfaces import ExecutionContainerCreator


class Authenticator:

    @staticmethod
    def authenticate(username: str, password: str) -> Optional[Dict]:
        if username == "user" and password == "password":
            return {"user_id": 123, "username": username}
        return None


class ExecutionContainer(ExecutionContainerCreator):
    def __init__(self):
        self.encoder = JWTEncoder()
        self.decoder = JWTDecoder()
        self.authenticator = Authenticator()
        self.key_serializer = PEMKeySerializer()
        self.key_persistence = FileKeyPersistence()
        self.key_management = RSAKeyPairGenerator(
            key_serializer=self.key_serializer,
            key_persistence=self.key_persistence,
        )
        self.token_manager = self._create_token_manager()

    def _create_token_manager(self):
        return TokenManager(
            self.key_management,
            self.encoder,
            self.decoder,
            self.authenticator
        )

    def create_token(self, username: str, password: str) -> Optional[str]:
        return self.token_manager.create_user_token(username, password)
