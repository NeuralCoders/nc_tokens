from nc_tokens.token_creator import TokenCreatorManager


token_creator = TokenCreatorManager(
    spaces_bucket="dev-portal-web-esph",
    spaces_region="nyc3",
    access_key_id="DO00VUJUDJ3RHXHG7FMV",
    secret_access_key="4z0rpdPqAmysgITyPk+/MYEwoEzMBuqIBvLmECjxpbU",
)

if __name__ == '__main__':
    payload = {
        "iss": "iss",
        "sub": "sub",
        "aud": "jti",
        "exp": 1724377087629,
        "iat": 128937218974,
        "nbf": "bf",
        "token_type": "user"
    }

    token = token_creator.create_user_token(payload)
    token_decoded = token_creator.validate_token(token)
    print(token)
    print("------")
    print(token_decoded)

    service_payload = {
        "iss": "iss",
        "sub": "sub",
        "aud": "jti",
        "exp": 2724377087629,
        "iat": 1724377087629,
        "nbf": "bf",
        "service_name": "service_name",
        "token_type": "service"
    }

    token = token_creator.create_service_token(service_payload)
    token_decoded = token_creator.validate_token(token)
    print(token)
    print("------")
    print(token_decoded)
