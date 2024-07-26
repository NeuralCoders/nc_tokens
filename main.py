from src.rsa_token_lib import RSAKeyPairGenerator, JWTEncoder, JWTDecoder
from src.token_manager import TokenManager
from typing import Optional, Dict


class Authenticator:

    @staticmethod
    def authenticate(username: str, password: str) -> Optional[Dict]:
        if username == "user" and password == "password":
            return {"user_id": 123, "username": username}
        return None


def main():
    key_generator = RSAKeyPairGenerator()
    encoder = JWTEncoder()
    decoder = JWTDecoder()
    authenticator = Authenticator()

    token_manager = TokenManager(key_generator, encoder, decoder,
                                 authenticator)

    username = "user"
    password = "password"
    token = token_manager.create_token(username, password)

    if token:
        print(f"Token creado: {token}")

        try:
            decoded_payload = token_manager.validate_token(token)
            print(f"Token válido. Payload: {decoded_payload}")
        except ValueError as e:
            print(f"Token inválido: {str(e)}")
    else:
        print("Autenticación fallida")

    invalid_token = "esrtaj984389dasn"
    try:
        token_manager.validate_token(invalid_token)
    except ValueError as e:
        print(f"{str(e)}")


if __name__ == "__main__":
    main()
