# cert_scanner
Python Based SSL/TLS scanner
## Set Up 

1. Download the code 
2. Run `make install` and `source .venv/bin/activate` to install dependencies and set up virtual environement
3. Run `python cert_scanner/scanner.py` for usage

```
git clone git@github.com:Zakaria-Kofiro/cert_scanner.git
cd cert_scanner
make install
source .venv/bin/activate
python cert_scanner/scanner.py
```
## Usage
```
Usage: scanner.py [OPTIONS]

Options:
  -h, --hostname TEXT  Get SSL/TLS certificate for given hostname
  -c, --cert TEXT      Queries cert against crt.sh (crt.sh id, sha1, or
                       sha256)
  --help               Show this message and exit.
```


## Testing
- `make test-all`: Run all unit tests
- `make test`: Run all unit tests mainly testing the main code and helper functions, excludes API heavy calls (fast)
- `make test-data`: Run tests that test lists of valid/invalid inputs, mostly testing the crt.sh API (slow)
