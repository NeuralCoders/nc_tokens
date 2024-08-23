from typing import Optional
from ..rsa_token_lib import SpacesKeyLoader, SpacesConfig
from ..token_manager import TokenManager, JWTDecoder, JWTEncoder
from .interfaces import TokenCreator
import datetime


class TokenCreatorManager(TokenCreator):
    def __init__(
            self,
            spaces_bucket: str,
            spaces_region: str,
            access_key_id: str,
            secret_access_key: str,
    ):
        self.encoder = JWTEncoder()
        self.decoder = JWTDecoder()
        self.spaces_config = SpacesConfig(
            spaces_bucket=spaces_bucket,
            spaces_region=spaces_region,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key
        )
        self.key_management = SpacesKeyLoader(
            configuration=self.spaces_config
        )
        self.token_manager = self._create_token_manager()

    def _create_token_manager(self):
        return TokenManager(
            self.key_management,
            self.encoder,
            self.decoder
        )

    def create_user_token(self, payload: dict) -> Optional[str]:
        return self.token_manager.create_user_token(payload=payload)

    def create_service_token(self, payload: dict) -> Optional[str]:
        return self.token_manager.create_service_token(payload=payload)

    def validate_token(self, token: str) -> dict:
        return self.token_manager.validate_token(token)
