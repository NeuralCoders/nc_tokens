import unittest
from typing import Optional, Dict
from src.rsa_token_lib import JWTEncoder, JWTDecoder, RSAKeyPairGenerator
from src.token_manager import TokenManager


class Authenticator:

    @staticmethod
    def authenticate(username: str, password: str) -> Optional[Dict]:
        if username == "user" and password == "password":
            return {"user_id": 123, "username": username}
        return None


class TestJWTManager(unittest.TestCase):
    def setUp(self):
        self.key_generator = RSAKeyPairGenerator()
        self.private_key, self.public_key = self.key_generator.generate_keys()
        self.encoder = JWTEncoder()
        self.decoder = JWTDecoder()
        self.authenticator = Authenticator()
        self.token_manager = TokenManager(
            self.key_generator,
            self.encoder,
            self.decoder,
            self.authenticator
        )

    def test_jwt_encoder(self):
        """Test JWT encoder."""
        payload = {"user_id": 123, "username": "testuser"}
        token = self.encoder.encode(payload, self.private_key)
        self.assertIsInstance(token, str)
        self.assertEqual(token.count('.'), 2)

    def test_jwt_decoder_valid_token(self):
        """Test JWT decoder valid token."""
        payload = {"user_id": 123, "username": "testuser"}
        token = self.encoder.encode(payload, self.private_key)
        decoded_payload = self.decoder.decode(token, self.public_key)
        self.assertEqual(decoded_payload, payload)

    def test_jwt_decoder_invalid_token(self):
        """test JWT decoder invalid token."""
        invalid_token = "invalid.token.here"
        with self.assertRaises(ValueError):
            self.decoder.decode(invalid_token, self.public_key)

    def test_token_manager_create_token_valid_credentials(self):
        """Test token manager creating a token."""
        token = self.token_manager.create_user_token(
            "user",
            "password"
        )
        self.assertIsInstance(token, str)
        self.assertEqual(token.count('.'), 2)

    def test_token_manager_create_token_invalid_credentials(self):
        """Test token manager creating a token."""
        token = self.token_manager.create_user_token(
            "invalid_user",
            "invalid_password"
        )
        self.assertIsNone(token)

    def test_token_manager_validate_token_valid(self):
        """Test token manager validation."""
        token = self.token_manager.create_user_token(
            "user",
            "password"
        )
        decoded_payload = self.token_manager.validate_token(token)
        self.assertIsInstance(decoded_payload, dict)
        self.assertIn("user_id", decoded_payload)
        self.assertIn("username", decoded_payload)

    def test_token_manager_validate_token_invalid(self):
        """Test token manager validation."""
        invalid_token = "invalid.token.here"
        with self.assertRaises(ValueError):
            self.token_manager.validate_token(invalid_token)

    def test_token_manager_end_to_end(self):
        """Test token manager end-to-end as an endpoint or user"""
        # ---------------------------------------------------------------------
        # Verify token
        # ---------------------------------------------------------------------
        token = self.token_manager.create_user_token(
            "user",
            "password"
        )
        self.assertIsNotNone(token)

        # ---------------------------------------------------------------------
        # Validate token
        # ---------------------------------------------------------------------
        decoded_payload = self.token_manager.validate_token(token)
        self.assertEqual(decoded_payload["username"], "user")
        self.assertIn("user_id", decoded_payload)

        # ---------------------------------------------------------------------
        # Validate an invalid token
        # ---------------------------------------------------------------------
        with self.assertRaises(ValueError):
            self.token_manager.validate_token("invalid.token.here")

        # ---------------------------------------------------------------------
        # Try to create a token with invalid credentials
        # ---------------------------------------------------------------------
        invalid_token = self.token_manager.create_user_token(
            "invalid_user",
            "invalid_password"
        )
        self.assertIsNone(invalid_token)


if __name__ == '__main__':
    unittest.main()
