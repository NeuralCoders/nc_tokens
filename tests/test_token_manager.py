import unittest
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from src.token_manager import TokenManager


class TestTokenManager(unittest.TestCase):

    def setUp(self):
        self.key_loader = Mock()
        self.encoder = Mock()
        self.decoder = Mock()
        self.private_key = Mock(spec=rsa.RSAPrivateKey)
        self.public_key = Mock(spec=rsa.RSAPublicKey)

        self.key_loader.load_keys.return_value = (
        self.private_key, self.public_key)

        self.token_manager = TokenManager(self.key_loader, self.encoder,
                                          self.decoder)

    def test_init_loads_keys(self):
        self.key_loader.load_keys.assert_called_once()
        self.assertEqual(self.token_manager.private_key, self.private_key)
        self.assertEqual(self.token_manager.public_key, self.public_key)

    def test_create_user_token(self):
        username = "testuser"
        password = "testpass"
        expected_token = "user_token"

        self.encoder.encode.return_value = expected_token

        token = self.token_manager.create_user_token(username, password)

        self.encoder.encode.assert_called_once_with(
            {"user_id": username, "username": password},
            self.private_key,
            token_type='user'
        )
        self.assertEqual(token, expected_token)

    def test_create_service_token(self):
        service_id = "test_service"
        expected_token = "service_token"

        self.encoder.encode.return_value = expected_token

        token = self.token_manager.create_service_token(service_id)

        self.encoder.encode.assert_called_once_with(
            {"service_id": service_id},
            self.private_key,
            token_type='service'
        )
        self.assertEqual(token, expected_token)

    def test_validate_token_valid(self):
        valid_token = "valid_token"
        self.decoder.decode.return_value = {"some": "payload"}

        result = self.token_manager.validate_token(valid_token)

        self.decoder.decode.assert_called_once_with(valid_token,
                                                    self.public_key)
        self.assertTrue(result)

    def test_validate_token_invalid(self):
        invalid_token = "invalid_token"
        self.decoder.decode.side_effect = ValueError("Invalid token")

        result = self.token_manager.validate_token(invalid_token)

        self.decoder.decode.assert_called_once_with(invalid_token,
                                                    self.public_key)
        self.assertFalse(result)

    @patch('datetime.datetime')  # Asegúrate de que la ruta de importación sea correcta
    def test_token_expiration(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now

        self.token_manager.create_user_token("user", "pass")
        self.encoder.encode.assert_called_with(
            {"user_id": "user", "username": "pass"},
            self.private_key,
            token_type='user'
        )

        mock_datetime.utcnow.return_value = now + timedelta(seconds=11)

        self.decoder.decode.side_effect = ValueError("Token has expired")
        result = self.token_manager.validate_token("expired_token")
        self.assertFalse(result)

        mock_datetime.utcnow.return_value = now
        self.token_manager.create_service_token("service")
        self.encoder.encode.assert_called_with(
            {"service_id": "service"},
            self.private_key,
            token_type='service'
        )

        mock_datetime.utcnow.return_value = now + timedelta(minutes=14)

        self.decoder.decode.side_effect = None
        self.decoder.decode.return_value = {"service_id": "service"}
        result = self.token_manager.validate_token("service_token")
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()