# Makefile
# Provides developer shortcuts for setup, linting, testing, and container commands.

.PHONY: test lint

test:
	pytest tests

lint:
	ruff check .
	mypy src

