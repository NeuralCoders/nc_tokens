import datetime

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

    def create_user_token(self, payload: dict) -> Optional[str]:
        """
        Creates a new user token with the given payload

        example:

        payload = {
            "iss": "iss",
            "sub": "sub",
            "aud": "jti",
            "exp": datetime.datetime.timestamp(),
            "iat": 128937218974,
            "nbf": "bf",
            "token_type": "user"
        }

        :param payload:
        :return: encoded token or None if authentication fails
        """
        return self.encoder.encode(
            payload,
            self.private_key,
            token_type=payload["token_type"]
        )

    def create_service_token(self, payload: dict) -> str:
        """
        Creates a new service token with the given payload

        example:

        payload = {
            "iss": "iss",
            "sub": "sub",
            "aud": "jti",
            "exp": datetime.datetime.timestamp(),
            "iat": 128937218974,
            "nbf": "bf",
            "service_name": "service_name",
            "token_type": "service"
        }

        :param payload:
        :return: encoded token
        """
        return self.encoder.encode(
            payload,
            self.private_key,
            token_type=payload['token_type']
        )

    def validate_token(self, token: str) -> dict:
        """
        Validates the given token.
        :param token: token to validate
        :return: True if the token is valid, False otherwise
        """
        try:
            return self.decoder.decode(token, self.public_key)
        except ValueError as error:
            return {
                'error': str(error)
            }
