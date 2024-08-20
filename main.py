from src.execution_library import TokenCreatorManager

if __name__ == '__main__':
    execute = TokenCreatorManager(
        spaces_bucket="dev-portal-web-esph",
        spaces_region="nyc3",
        access_key_id="DO00VUJUDJ3RHXHG7FMV",
        secret_access_key="4z0rpdPqAmysgITyPk+/MYEwoEzMBuqIBvLmECjxpbU",
    )
    token = execute.create_user_token(
        username="testing",
        password="password"
    )
    print(token)
    print(execute.validate_token(token))
