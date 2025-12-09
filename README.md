# Simple HTTP Server

A simplest HTTP server inspired by Python's built-in `http.server` module.

## Overview

This project provides a lightweight and easy-to-use HTTP server implementation in Python. It's designed to be simple yet extensible, making it perfect for development, testing, and learning purposes.

## Features

- 🚀 Simple and intuitive API
- 📦 Minimal dependencies
- 🔧 Easy to extend and customize
- 🧪 Well-tested with comprehensive test coverage
- 📝 Type hints for better IDE support

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/plantree/simple-http-server.git
cd simple-http-server

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .
```

### For Development

```bash
# Install development dependencies
make install-dev
```

## Usage

```python
from simple_http_server.main import main

# Start the server
main()
```

## Development

### Prerequisites

- Python 3.8 or higher
- pip

### Setup

1. Clone the repository and navigate to the project directory
2. Create and activate a virtual environment
3. Install development dependencies:

```bash
make install-dev
```

### Running Tests

```bash
# Run all tests with coverage
make test

# Run tests with pytest directly
pytest

# Run tests with coverage report
pytest --cov=src --cov-report=html
```

### Code Quality

This project uses several tools to maintain code quality:

```bash
# Format code with Black and isort
make format

# Run linters
make lint

# Run individual tools
black src tests
isort src tests
flake8 src tests
mypy src
pylint src
```

### Available Make Commands

```bash
make help          # Show available commands
make install       # Install production dependencies
make install-dev   # Install development dependencies
make test          # Run tests with coverage
make lint          # Run all linters
make format        # Format code
make clean         # Remove build artifacts
make build         # Build distribution packages
```

## Project Structure

```
simple-http-server/
├── src/
│   └── simple_http_server/     # Main package
│       ├── __init__.py
│       └── main.py
├── tests/                       # Test files
│   ├── __init__.py
│   └── test_main.py
├── .flake8                      # Flake8 configuration
├── .gitignore                   # Git ignore rules
├── .pylintrc                    # Pylint configuration
├── CHANGELOG.md                 # Version history
├── CONTRIBUTING.md              # Contribution guidelines
├── LICENSE                      # License file
├── Makefile                     # Development commands
├── pyproject.toml               # Project configuration
├── README.md                    # This file
├── requirements.txt             # Production dependencies
├── requirements-dev.txt         # Development dependencies
└── setup.py                     # Package setup
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linters (`make test && make lint`)
5. Format your code (`make format`)
6. Commit your changes (`git commit -m 'Add some amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes in each version.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Inspiration

This project is inspired by Python's built-in [`http.server`](https://docs.python.org/3/library/http.server.html) module, aiming to provide a cleaner and more extensible implementation.

## Contact

- Repository: [https://github.com/plantree/simple-http-server](https://github.com/plantree/simple-http-server)
- Issues: [https://github.com/plantree/simple-http-server/issues](https://github.com/plantree/simple-http-server/issues)

## Acknowledgments

- Python's `http.server` module for inspiration
- The Python community for excellent tools and libraries

## Reference

- https://github.com/python/cpython/blob/3.14/Lib/http/server.py