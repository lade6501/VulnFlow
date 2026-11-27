# Makefile
# Provides developer shortcuts for setup, linting, testing, and container commands.

.PHONY: check test lint test-gate

PYTHON ?= python

test:
	$(PYTHON) -m pytest

check: lint test test-gate

lint:
	$(PYTHON) -m ruff check src api tests evals
	$(PYTHON) -m mypy

test-gate:
	LANGCHAIN_TRACING_V2=false $(PYTHON) -m evals.deepeval_suite

