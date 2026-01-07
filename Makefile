.PHONY: help install install-dev test lint format clean build

help:
	@echo "Available commands:"
	@echo "  make install       Install production dependencies"
	@echo "  make test          Run tests with coverage"
	@echo "  make lint          Run linters (flake8, mypy, pylint)"
	@echo "  make format        Format code with black and isort"
	@echo "  make clean         Remove build artifacts and cache files"
	@echo "  make build         Build distribution packages"

install:
	pip install -r requirements.txt

test:
	pytest

run:
	python -m src.http.server 8002

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
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build
