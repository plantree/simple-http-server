# Contributing to Simple HTTP Server

Thank you for your interest in contributing to this project!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/plantree/simple-http-server.git
cd simple-http-server
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
make install-dev
```

## Development Workflow

### Running Tests
```bash
make test
```

### Code Formatting
```bash
make format
```

### Linting
```bash
make lint
```

### Building
```bash
make build
```

## Code Style

This project uses:
- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking
- **pylint** for additional code quality checks

## Pull Request Process

1. Create a new branch for your feature or bug fix
2. Write tests for your changes
3. Ensure all tests pass and code is properly formatted
4. Submit a pull request with a clear description of your changes
