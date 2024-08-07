from abc import ABC, abstractmethod
from typing import Optional, Dict


class Authenticator(ABC):
    @abstractmethod
    def authenticate(self, **kwargs) -> Optional[Dict]:
        """
        Authenticate a user with the given username and password. It's a
        flexible function to use from outside and call it using an
        Authenticator personalized class with username and password.
        :return:
        """
        raise NotImplementedError
