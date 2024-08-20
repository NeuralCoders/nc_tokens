import unittest
from unittest.mock import Mock
from src.token_manager.token_management import TokenManager
from src.rsa_token_lib import KeyPairGenerator
from src.token_manager.token_encoder_decoder import JWTEncoder, JWTDecoder


class TestTokenManager(unittest.TestCase):
    def setUp(self):
        self.key_management = Mock(spec=KeyPairGenerator)
        self.encoder = Mock(spec=JWTEncoder)
        self.decoder = Mock(spec=JWTDecoder)

        self.private_key = Mock()
        self.public_key = Mock()
        self.key_management.load_keys.return_value = (
            self.private_key, self.public_key
        )

        self.token_manager = TokenManager(
            self.key_management,
            self.encoder,
            self.decoder
        )

    def test_init(self):
        # ---------------------------------------------------------------------
        # Verify that the keys are loaded during initialization
        # ---------------------------------------------------------------------
        self.key_management.load_keys.assert_called_once()
        self.assertEqual(self.token_manager.private_key, self.private_key)
        self.assertEqual(self.token_manager.public_key, self.public_key)

    def test_create_user_token_success(self):
        username = "testuser"
        password = "testpass"
        self.encoder.encode.return_value = "encoded_token"

        token = self.token_manager.create_user_token(username, password)

        # ---------------------------------------------------------------------
        # Verify that the token is created correctly when authentication
        # succeeds
        # ---------------------------------------------------------------------

        self.assertEqual(token, "encoded_token")

    def test_create_service_token_success(self):
        service_id = "1"
        self.encoder.encode.return_value = "encoded_token"

        token = self.token_manager.create_service_token(service_id)
        # ---------------------------------------------------------------------
        # Verify that the token is created correctly
        # ---------------------------------------------------------------------

        self.assertEqual(token, "encoded_token")

    def test_validate_token(self):
        token = "test_token"
        decoded_payload = {"user_id": 1, "username": "testuser"}
        self.decoder.decode.return_value = decoded_payload

        result = self.token_manager.validate_token(token)

        # ---------------------------------------------------------------------
        # Verify that the token is correctly validated
        # ---------------------------------------------------------------------
        self.decoder.decode.assert_called_once_with(token, self.public_key)
        self.assertEqual(result, True)


if __name__ == '__main__':
    unittest.main()
