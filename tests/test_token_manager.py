import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from nc_tokens.token_manager import JWTEncoder, JWTDecoder
from nc_tokens.rsa_token_lib import KeyLoader
from nc_tokens.token_manager import TokenManager


class TestTokenManager(unittest.TestCase):

    def setUp(self):
        self.mock_key_loader = Mock(spec=KeyLoader)
        self.mock_encoder = Mock(spec=JWTEncoder)
        self.mock_decoder = Mock(spec=JWTDecoder)

        self.mock_private_key = Mock(spec=rsa.RSAPrivateKey)
        self.mock_public_key = Mock(spec=rsa.RSAPublicKey)

        self.mock_key_loader.load_keys.return_value = (
            self.mock_private_key, self.mock_public_key
        )

        self.token_manager = TokenManager(self.mock_key_loader,
                                          self.mock_encoder, self.mock_decoder)

    def test_init(self):
        self.assertEqual(self.token_manager.private_key, self.mock_private_key)
        self.assertEqual(self.token_manager.public_key, self.mock_public_key)
        self.mock_key_loader.load_keys.assert_called_once()

    def test_create_user_token(self):
        payload = {
            "iss": "test_issuer",
            "sub": "test_subject",
            "aud": "test_audience",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "nbf": int(datetime.utcnow().timestamp()),
            "token_type": "user"
        }
        expected_token = "test_user_token"
        self.mock_encoder.encode.return_value = expected_token

        result = self.token_manager.create_user_token(payload)

        self.assertEqual(result, expected_token)
        self.mock_encoder.encode.assert_called_once_with(
            payload,
            self.mock_private_key,
            token_type="user"
        )

    def test_create_service_token(self):
        payload = {
            "iss": "test_issuer",
            "sub": "test_subject",
            "aud": "test_audience",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "nbf": int(datetime.utcnow().timestamp()),
            "service_name": "test_service",
            "token_type": "service"
        }
        expected_token = "test_service_token"
        self.mock_encoder.encode.return_value = expected_token

        result = self.token_manager.create_service_token(payload)

        self.assertEqual(result, expected_token)
        self.mock_encoder.encode.assert_called_once_with(
            payload,
            self.mock_private_key,
            token_type="service"
        )

    def test_validate_token_success(self):
        token = "valid_token"
        expected_payload = {"sub": "test_subject", "exp": int(
            (datetime.utcnow() + timedelta(hours=1)).timestamp())}
        self.mock_decoder.decode.return_value = expected_payload

        result = self.token_manager.validate_token(token)

        self.assertEqual(result, expected_payload)
        self.mock_decoder.decode.assert_called_once_with(
            token,
            self.mock_public_key
        )

    def test_validate_token_failure(self):
        token = "invalid_token"
        self.mock_decoder.decode.side_effect = ValueError("Token has expired")

        result = self.token_manager.validate_token(token)

        self.assertEqual(result, {'error': 'Token has expired'})
        self.mock_decoder.decode.assert_called_once_with(
            token,
            self.mock_public_key
        )


if __name__ == '__main__':
    unittest.main()
