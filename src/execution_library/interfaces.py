from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa


class ExecutionContainerCreator(ABC):

    @abstractmethod
    def create_token(self, username: str, password: str) -> str:
        raise NotImplementedError
