.PHONY: help install install-dev test lint format clean build run run-https cert

help:
	@echo "Available commands:"
	@echo "  make install       Install production dependencies"
	@echo "  make test          Run tests with coverage"
	@echo "  make lint          Run linters (flake8, mypy, pylint)"
	@echo "  make format        Format code with black and isort"
	@echo "  make clean         Remove build artifacts and cache files"
	@echo "  make build         Build distribution packages"
	@echo "  make run           Run HTTP server on port 8002"
	@echo "  make run-https     Run HTTPS server on port 8443"
	@echo "  make cert          Generate self-signed certificate"

install:
	pip install -r requirements.txt

test:
	pytest

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

run:
	python -m src.http.server 8002

run-https:
	@test -f cert.pem || (echo "Certificate not found. Run 'make cert' first." && exit 1)
	python -m src.http.server --tls-cert cert.pem --tls-key key.pem 8443

lint:
	flake8 src tests
	mypy src
	pylint src

format:
	black src tests
	isort src tests

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -f cert.pem key.pem
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build
