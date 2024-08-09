from abc import ABC, abstractmethod
from typing import Tuple, Any


class ExecutionContainerCreator(ABC):

    @abstractmethod
    def initialize_keys(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def load_keys(self) -> Tuple[Any, Any]:
        raise NotImplementedError
