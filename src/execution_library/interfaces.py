from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa


class ExecutionContainerCreator(ABC):

    @abstractmethod
    def create_user_token(self, username: str, password: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def validate_token(self, token: str) -> bool:
        raise NotImplementedError
