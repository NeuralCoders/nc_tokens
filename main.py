from src.execution_library import ExecutionContainer

if __name__ == '__main__':
    execute = ExecutionContainer()
    token = execute.create_service_token("service")
    print(token)
    print(execute.validate_token(token))
