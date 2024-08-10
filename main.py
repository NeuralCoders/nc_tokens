from src.execution_library import ExecutionContainer

if __name__ == '__main__':
    execute = ExecutionContainer()
    print(execute.create_token(username="user", password="password"))
