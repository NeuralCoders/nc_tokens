from ..rsa_token_lib import JWTEncoder, JWTDecoder
from typing import Optional, Dict
from .interfaces import Authenticator


class TokenManager:
    """Token management class"""
    def __init__(
            self,
            execution_container,
            encoder: JWTEncoder,
            decoder: JWTDecoder,
            authenticator: Authenticator
    ):
        self.execution = execution_container
        self.encoder = encoder
        self.decoder = decoder
        self.authenticator = authenticator
        self.private_key = None
        self.public_key = None
        self._load_keys()

    def _load_keys(self):
        self.private_key, self.public_key = self.execution.load_keys()

    def create_token(self, username: str, password: str) -> Optional[str]:
        """
        Creates a new token with the given username and password.
        :param username: username
        :param password: password
        :return:
        """
        user_data = self.authenticator.authenticate(username, password)
        if user_data:
            payload = {
                "user_id": user_data["user_id"],
                "username": user_data["username"],
            }
            return self.encoder.encode(payload, self.private_key)
        return None

    def validate_token(self, token: str) -> Dict:
        """
        Validates the given token.
        :param token: token to validate
        :return:
        """
        return self.decoder.decode(token, self.public_key)
