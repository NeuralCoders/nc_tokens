from src.execution_library import ExecutionContainer, AppConfig

if __name__ == '__main__':
    execute = ExecutionContainer(config=AppConfig())
    print(execute.create_token(username="user", password="password"))
