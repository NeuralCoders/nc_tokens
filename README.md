# Neural Coders Tokens Library 0.0.1

## How to use

- Create a bucket space on AWS or Digital Ocean Spaces 
- Generate a private Key and Public key RSA 2048 (**called them private_key.pem and public_key.pem**)

### If the keys don't exist

```
openssl genrsa -out private_key.pem 2048
```

```
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

- Upload the keys to the created bucket 
- Create an access key and secret access key

### How to call the library

- Install the library

```
pip install git+https://github.com/NeuralCoders/nc_tokens.git
```

- Call the function `TokenCreatorManager` in your python code from this library and use it like: 

```python
from nc_tokens.token_creator import TokenCreatorManager

token_manager = TokenCreatorManager(
        spaces_bucket="<spaces bucket name>",
        spaces_region="<bucket region name>",
        access_key_id="<access key>",
        secret_access_key="<secret access key>",
    )
```

### Create a user token

```python
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
```

### Create a service token

```python
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
```

### Validate token

```python
token_validated = token_manager.validate_token(
    token="<token>"
)
```

## Next improvements of the library

- Add logs