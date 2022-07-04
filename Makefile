test:
	python3 -m pytest tests/ --disable-pytest-warnings

test-clean:
	rm -rf tests/cert_scanner/__pycache__