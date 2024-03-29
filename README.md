# <img src="cert_logo.png" width="22"/> cert_scanner 

<img src="cert_scanner/web_app/static/images/logo.png" width=300>


<pre>
Python Based SSL/TLS scanner
</pre>



## Set Up 

1. Download the code 
2. Run `make install` and `source .venv/bin/activate` to install dependencies and set up virtual environment
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
  -c, --cert TEXT      Queries cert against crt.sh (crt.sh id, SHA1, or
                       SHA256)
  --help               Show this message and exit.
```

## Web Application 

<img src="webpage.png">

### Run Flask Web App Locally
```
cd cert_scanner/web_app/app.py
python3 -m flask run
```




## Docker
### Build Image (CLI)
`docker build -f Dockerfile.cli --tag <tag> .`

### Run Image (CLI)
`docker run <tag> --help`

## Testing
- `make test-all`: Run all unit tests
- `make test`: Run unit tests testing the main code and helper functions 
- `make test-data`: Run tests on lists of valid/invalid inputs. It's mostly testing the crt.sh API, which takes some time processing the all the inputs