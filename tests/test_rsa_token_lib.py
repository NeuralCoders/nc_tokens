import unittest
from cryptography.hazmat.primitives.asymmetric import rsa
from src.rsa_token_lib import RSAKeyPairGenerator


class TestRSAKeyPairGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = RSAKeyPairGenerator()

    def test_default_key_generation(self):
        """
        Tests that the default key generation works as expected.
        :return:
        """
        private_key, public_key = self.generator.generate_keys()

        # ---------------------------------------------------------------------
        # Verify that the keys are the correct type
        # ---------------------------------------------------------------------
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)

        # ---------------------------------------------------------------------
        # Verify the key size is correct
        # ---------------------------------------------------------------------
        self.assertEqual(private_key.key_size, 2048)
        self.assertEqual(public_key.key_size, 2048)

        # ---------------------------------------------------------------------
        # Verify that the public exponent is the waited
        # ---------------------------------------------------------------------
        self.assertEqual(
            private_key.public_key().public_numbers().e,
            65537
        )
        self.assertEqual(public_key.public_numbers().e, 65537)

    def test_custom_key_generation(self):
        """
        Test that custom key generation works as espected
        :return:
        """

        custom_generator = RSAKeyPairGenerator(
            public_exponent=3,
            key_size=3072
        )
        private_key, public_key = custom_generator.generate_keys()

        # ---------------------------------------------------------------------
        # Verify the custom size key is the waited
        # ---------------------------------------------------------------------
        self.assertEqual(private_key.key_size, 3072)
        self.assertEqual(public_key.key_size, 3072)

        # ---------------------------------------------------------------------
        # Verify that the public exponent is the waited
        # ---------------------------------------------------------------------
        self.assertEqual(private_key.public_key().public_numbers().e, 3)
        self.assertEqual(public_key.public_numbers().e, 3)

    def test_public_key_matches_private_key(self):
        """
        Test that public key matches with the private key
        :return:
        """
        private_key, public_key = self.generator.generate_keys()

        # ---------------------------------------------------------------------
        # Verify that the public key is derivative from the private key
        # ---------------------------------------------------------------------
        self.assertEqual(
            private_key.public_key().public_numbers(),
            public_key.public_numbers()
        )


if __name__ == '__main__':
    unittest.main()
