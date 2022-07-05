install: venv
	source .venv/bin/activate && pip install -r requirements.txt

venv:
	test -d .venv || python3 -m venv .venv

# make test: tests the main code, including CLI and helper function
test:
	python3 -m pytest tests/ --disable-pytest-warnings --show-capture=no --ignore=tests/cert_scanner/test_scan_data.py 

# make test-data: mainly tests the crt.sh API using list of valid/invalid inputs - takes few minutes to run
test-data:
	python3 -m pytest tests/cert_scanner/test_scan_data.py --disable-pytest-warnings --show-capture=no

test-all: test test-data

clean:
	rm -rf .venv
	rm -rf .pytest_cache
	rm -rf cert_scanner/__pycache__
	rm -rf cert_scanner/.pytest_cache
	rm -rf tests/__pycache__
	rm -rf tests/cert_scanner/__pycache__
	rm -rf tests/cert_scanner/data/__pycache__