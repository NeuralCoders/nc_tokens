import unittest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from src.rsa_token_lib import SpacesConfig, SpacesKeyLoader


class TestSpacesKeyLoader(unittest.TestCase):

    def setUp(self):
        self.config = SpacesConfig(
            spaces_bucket="test-bucket",
            spaces_region="nyc3",
            access_key_id="test-access-key",
            secret_access_key="test-secret-key",
            private_key_name="private_key.pem",
            public_key_name="public_key.pem"
        )

    @patch('boto3.session.Session')
    def test_init_validates_bucket(self, mock_session):
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.head_bucket.return_value = True

        SpacesKeyLoader(self.config)

        mock_client.head_bucket.assert_called_once_with(Bucket="test-bucket")

    @patch('boto3.session.Session')
    def test_init_raises_value_error_on_404(self, mock_session):
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.head_bucket.side_effect = ClientError(
            {'Error': {'Code': '404'}},
            'HeadBucket'
        )

        with self.assertRaises(ValueError):
            SpacesKeyLoader(self.config)

    @patch('boto3.session.Session')
    def test_init_raises_permission_error_on_403(self, mock_session):
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.head_bucket.side_effect = ClientError(
            {'Error': {'Code': '403'}},
            'HeadBucket'
        )

        with self.assertRaises(PermissionError):
            SpacesKeyLoader(self.config)

    @patch('boto3.session.Session')
    def test_load_key_success(self, mock_session):
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.head_bucket.return_value = True
        mock_client.get_object.return_value = {'Body': Mock(read=lambda: b'test-key-data')}

        loader = SpacesKeyLoader(self.config)
        key_data = loader._load_key("test_key.pem")

        self.assertEqual(key_data, b'test-key-data')
        mock_client.get_object.assert_called_once_with(Bucket="test-bucket", Key="test_key.pem")

    @patch('boto3.session.Session')
    def test_load_key_not_found(self, mock_session):
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.head_bucket.return_value = True
        mock_client.get_object.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchKey'}},
            'GetObject'
        )

        loader = SpacesKeyLoader(self.config)
        with self.assertRaises(FileNotFoundError):
            loader._load_key("non_existent_key.pem")

    @patch('boto3.session.Session')
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('cryptography.hazmat.primitives.serialization.load_pem_public_key')
    def test_load_keys_success(
            self,
            mock_load_public,
            mock_load_private, mock_session
    ):
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.head_bucket.return_value = True
        mock_client.get_object.side_effect = [
            {'Body': Mock(read=lambda: b'private-key-data')},
            {'Body': Mock(read=lambda: b'public-key-data')}
        ]

        mock_private_key = Mock(spec=rsa.RSAPrivateKey)
        mock_public_key = Mock(spec=rsa.RSAPublicKey)
        mock_load_private.return_value = mock_private_key
        mock_load_public.return_value = mock_public_key

        loader = SpacesKeyLoader(self.config)
        private_key, public_key = loader.load_keys()

        self.assertEqual(private_key, mock_private_key)
        self.assertEqual(public_key, mock_public_key)
        mock_load_private.assert_called_once_with(
            b'private-key-data',
            password=None,
            backend=unittest.mock.ANY
        )
        mock_load_public.assert_called_once_with(
            b'public-key-data',
            backend=unittest.mock.ANY
        )


if __name__ == '__main__':
    unittest.main()