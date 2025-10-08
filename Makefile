.PHONY: install test lint clean docs

install:
	pip install -e ".[dev]"

test:
	pytest tests/

lint:
	flake8 src/smart_contract_security
	black src/smart_contract_security
	isort src/smart_contract_security

clean:
	@echo "Cleaning build artifacts..."
	@if [ -d "build" ]; then rm -rf build/; fi
	@if [ -d "dist" ]; then rm -rf dist/; fi
	@if [ -f "*.egg-info" ]; then rm -rf *.egg-info; fi
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docs:
	mkdocs build
