import unittest
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from src.rsa_token_lib.key_generators import RSAKeyPairGenerator, \
    PEMKeySerializer, FileKeyPersistence, AppConfig


class TestRSAKeyPairGenerator(unittest.TestCase):
    def setUp(self):
        self.key_serializer = PEMKeySerializer()
        self.key_persistence = FileKeyPersistence()
        self.generator = RSAKeyPairGenerator(self.key_serializer,
                                             self.key_persistence)
        self.config = AppConfig()

    def test_default_key_generation(self):
        private_key, public_key = self.generator.generate_keys()

        # ---------------------------------------------------------------------
        # Verify that the keys are the correct type
        # ---------------------------------------------------------------------
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)

    def test_generate_and_save_keys(self):
        private_key, public_key = self.generator.generate_and_save_keys(
            self.config.private_key_path,
            self.config.public_key_path,
            self.config.key_password
        )

        # ---------------------------------------------------------------------
        # Verify that the keys were generated and saved correctly
        # ---------------------------------------------------------------------
        self.assertTrue(os.path.exists(self.config.private_key_path))
        self.assertTrue(os.path.exists(self.config.public_key_path))

    def test_load_and_extract_keys(self):
        self.generator.generate_and_save_keys(
            self.config.private_key_path,
            self.config.public_key_path,
            self.config.key_password
        )

        loaded_private_key, loaded_public_key = self.generator.load_and_extract_keys(
            self.config.private_key_path,
            self.config.public_key_path,
            self.config.key_password
        )

        # ---------------------------------------------------------------------
        # Verify that the loaded keys are the correct type
        # ---------------------------------------------------------------------
        self.assertIsInstance(loaded_private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(loaded_public_key, rsa.RSAPublicKey)

    def tearDown(self):
        if os.path.exists(self.config.private_key_path):
            os.remove(self.config.private_key_path)
        if os.path.exists(self.config.public_key_path):
            os.remove(self.config.public_key_path)


class TestPEMKeySerializer(unittest.TestCase):
    def setUp(self):
        self.serializer = PEMKeySerializer()
        self.key_pair = RSAKeyPairGenerator(
            self.serializer,
            FileKeyPersistence()
        ).generate_keys()

    def test_serialize_private_key(self):
        private_key_bytes = self.serializer.serialize_private_key(
            self.key_pair[0], b'password')

        # ---------------------------------------------------------------------
        # Verify that the serialized private key is in bytes format
        # ---------------------------------------------------------------------
        self.assertIsInstance(private_key_bytes, bytes)

    def test_serialize_public_key(self):
        public_key_bytes = self.serializer.serialize_public_key(
            self.key_pair[1])

        # ---------------------------------------------------------------------
        # Verify that the serialized public key is in bytes format
        # ---------------------------------------------------------------------
        self.assertIsInstance(public_key_bytes, bytes)


class TestFileKeyPersistence(unittest.TestCase):
    def setUp(self):
        self.persistence = FileKeyPersistence()
        self.test_file = 'test_key.pem'
        self.test_data = b'Test key data'

    def test_save_and_load_key(self):
        self.persistence.save_key(self.test_data, self.test_file)

        # ---------------------------------------------------------------------
        # Verify that the key file was created
        # ---------------------------------------------------------------------
        self.assertTrue(os.path.exists(self.test_file))

        loaded_data = self.persistence.load_key(self.test_file)

        # ---------------------------------------------------------------------
        # Verify that the loaded data matches the original data
        # ---------------------------------------------------------------------
        self.assertEqual(loaded_data, self.test_data)

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)


if __name__ == '__main__':
    unittest.main()
