from .token_encoder_decoder import JWTEncoder, JWTDecoder
from typing import Optional
from ..rsa_token_lib import KeyLoader


class TokenManager:
    """Token management class"""
    def __init__(
            self,
            key_management: KeyLoader,
            encoder: JWTEncoder,
            decoder: JWTDecoder,
    ):
        self.key_management = key_management
        self.encoder = encoder
        self.decoder = decoder
        self.private_key = None
        self.public_key = None
        self._load_keys()

    def _load_keys(self):
        """
        Load private and public keys
        :return: private and public keys
        """
        self.private_key, self.public_key = self.key_management.load_keys()

    def create_user_token(self, username: str, password: str) -> Optional[str]:
        """
        Creates a new user token with the given username and password.
        :param username: username
        :param password: password
        :return: encoded token or None if authentication fails
        """
        payload = {
            "user_id": username,
            "username": password,
        }
        return self.encoder.encode(
            payload,
            self.private_key,
            token_type='user'
        )

    def create_service_token(self, service_id: str) -> str:
        """
        Creates a new service token with the given service ID.
        :param service_id: unique identifier for the service
        :return: encoded token
        """
        payload = {
            "service_id": service_id,
        }
        return self.encoder.encode(
            payload,
            self.private_key,
            token_type='service'
        )

    def validate_token(self, token: str) -> bool:
        """
        Validates the given token.
        :param token: token to validate
        :return: True if the token is valid, False otherwise
        """
        try:
            self.decoder.decode(token, self.public_key)
            return True
        except ValueError:
            return False
