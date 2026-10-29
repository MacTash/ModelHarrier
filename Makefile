.PHONY: install install-dev dev test lint typecheck clean corpus corpus-check

VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

install:
	python3 -m venv $(VENV)
	$(PIP) install -e .

install-dev: install
	$(PIP) install -e ".[dev]"

dev:
	$(PYTHON) -m model_harrier.cli

test:
	$(PYTHON) -m pytest tests/ -v --cov=model_harrier

lint:
	$(PYTHON) -m ruff check model_harrier/ tests/

typecheck:
	$(PYTHON) -m mypy model_harrier/

clean:
	rm -rf $(VENV) build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name *.pyc -delete 2>/dev/null || true

corpus:
	$(PYTHON) -m model_harrier.cli corpus init

corpus-check:
	$(PYTHON) -m model_harrier.cli corpus check
