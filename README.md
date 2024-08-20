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

- Call the function `TokenCreatorManager` in your python code from this library and use it like: 

```python
from nc_tokens import TokenCreatorManager

token_manager = TokenCreatorManager(
        spaces_bucket="<spaces bucket name>",
        spaces_region="<bucket region name>",
        access_key_id="<access key>",
        secret_access_key="<secret access key>",
    )
```

### Create a user token

```python
user_token = token_manager.create_user_token(
    username="<your username>",
    password="<your password>"
)
```

### Create a service token

```python
user_token = token_manager.create_service_token(
    service_id="<service id>"
)
```

### Validate token

```python
token_validated = token_manager.validate_token(
    token="<token>"
)
```

## Next improvements of the library

- Add logs