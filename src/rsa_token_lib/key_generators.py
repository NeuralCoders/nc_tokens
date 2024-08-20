from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple
from botocore.exceptions import ClientError
from .interfaces import KeyLoader
import boto3


@dataclass
class SpacesConfig:
    spaces_bucket: str
    spaces_region: str
    access_key_id: str
    secret_access_key: str
    private_key_name: str = "private_key.pem"
    public_key_name: str = "public_key.pem"


class SpacesKeyLoader(KeyLoader):
    def __init__(self, configuration: SpacesConfig):
        self.config = configuration
        self.session = boto3.session.Session()
        self.client = self.session.client(
            's3',
            region_name=configuration.spaces_region,
            endpoint_url=f'https://{configuration.spaces_region}'
                         f'.digitaloceanspaces.com',
            aws_access_key_id=configuration.access_key_id,
            aws_secret_access_key=configuration.secret_access_key
        )
        self._validate_bucket_exists()

    def _validate_bucket_exists(self):
        try:
            self.client.head_bucket(Bucket=self.config.spaces_bucket)
        except ClientError as error:
            error_code = error.response['Error']['Code']
            if error_code == '404':
                raise ValueError(
                    f"The bucket '{self.config.spaces_bucket}' does not "
                    f"exist in Digital Ocean Spaces."
                )
            elif error_code == '403':
                raise PermissionError(
                    f"You don't have permission to access the bucket '"
                    f"{self.config.spaces_bucket}'."
                )
            else:
                raise RuntimeError(
                    f"An error occurred while accessing the bucket '"
                    f"{self.config.spaces_bucket}': {str(error)}"
                )

    def _load_key(self, key_name: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.config.spaces_bucket,
                                              Key=key_name)
            return response['Body'].read()
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchKey':
                raise FileNotFoundError(
                    f"The key '{key_name}' does not exist in the bucket.")
            else:
                raise RuntimeError(
                    f"An error occurred while loading the key '{key_name}':"
                    f" {str(error)}"
                )

    def load_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key_bytes = self._load_key(self.config.private_key_name)
        public_key_bytes = self._load_key(self.config.public_key_name)

        rsa_private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )
        rsa_public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        return rsa_private_key, rsa_public_key
