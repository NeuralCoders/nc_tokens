from typing import Optional, Dict
from src.rsa_token_lib import (RSAKeyPairGenerator, PEMKeySerializer,
                               FileKeyPersistence)
from src.token_manager import TokenManager, JWTDecoder, JWTEncoder
from .interfaces import ExecutionContainerCreator


class ExecutionContainer(ExecutionContainerCreator):
    def __init__(self):
        self.encoder = JWTEncoder()
        self.decoder = JWTDecoder()
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
            self.decoder
        )

    def create_user_token(self, username: str, password: str) -> Optional[str]:
        return self.token_manager.create_user_token(username, password)

    def create_service_token(self, service_id: str) -> Optional[str]:
        return self.token_manager.create_service_token(service_id)

    def validate_token(self, token: str) -> bool:
        return self.token_manager.validate_token(token)
