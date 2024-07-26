from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from typing import Dict, Tuple
from .interfaces import TokenEncoder, TokenDecoder
import json
import base64


class JWTEncoder(TokenEncoder):
    """JWT encoder class"""
    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """
        Base64 encode data.
        :param data: bytes of data
        :return: string base64
        """
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def _create_header() -> Dict:
        """
        Create header
        :return: dictionary with
        """
        return {"alg": "RS256", "typ": "JWT"}

    def _encode_parts(self, header: Dict, payload: Dict) -> Tuple[str, str]:
        """
        Encode parts.
        :param header: header of the request
        :param payload: payload of the request
        :return: encoded header and encoded payload
        """
        encoded_header = self._base64url_encode(json.dumps(header).encode())
        encoded_payload = self._base64url_encode(json.dumps(payload).encode())
        return encoded_header, encoded_payload

    def _create_signature(
            self,
            signature_input: bytes,
            private_key: rsa.RSAPrivateKey
    ) -> str:
        signature = private_key.sign(
            signature_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return self._base64url_encode(signature)

    def encode(self, payload: Dict, private_key: rsa.RSAPrivateKey) -> str:
        """
        Encode payload.
        :param payload: payload
        :param private_key: private key with RSAPrivateKey
        :return: encoded string payload
        """
        header = self._create_header()
        encoded_header, encoded_payload = self._encode_parts(header, payload)
        signature_input = f"{encoded_header}.{encoded_payload}".encode()
        encoded_signature = self._create_signature(
            signature_input,
            private_key
        )
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


class JWTDecoder(TokenDecoder):
    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        """
        Base64 decode data.
        :param data: data string to pass to base64
        :return: base64 decoded data
        """
        padding_data = '=' * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data + padding_data)

    @staticmethod
    def _split_token(token: str) -> list[str]:
        """
        Split token by a dot.
        :param token: token
        :return: only the token
        """
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        return parts

    @staticmethod
    def _verify_signature(signature_input: bytes, signature: bytes,
                          public_key: rsa.RSAPublicKey):
        """
        verify signature.
        :param signature_input: input of the sign
        :param signature: signature
        :param public_key: public key from RSAPrivateKey
        :return:
        """
        try:
            public_key.verify(
                signature,
                signature_input,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            raise ValueError("Invalid signature")

    def _decode_payload(self, payload_b64: str) -> Dict:
        """
        Decode payload.
        :param payload_b64: payload in base64 format
        :return: json file with a decoded payload
        """
        try:
            payload_json = self._base64url_decode(payload_b64).decode('utf-8')
            return json.loads(payload_json)
        except json.JSONDecodeError:
            raise ValueError("Invalid payload format")

    def decode(self, token: str, public_key: rsa.RSAPublicKey) -> Dict:
        """
        Decode token.
        :param token: token
        :param public_key: public key
        :return: decoded payload
        """
        try:
            header_b64, payload_b64, signature_b64 = self._split_token(token)

            signature_input = f"{header_b64}.{payload_b64}".encode()
            signature = self._base64url_decode(signature_b64)

            self._verify_signature(signature_input, signature, public_key)

            return self._decode_payload(payload_b64)
        except Exception as e:
            raise ValueError(f"Invalid token: {str(e)}")
