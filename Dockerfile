FROM python:3.8-slim-buster

WORKDIR /app

COPY cert_scanner ./cert_scanner
COPY requirements ./requirements

RUN pip3 install pip==21.2
RUN pip3 install pip-tools
RUN python -m piptools sync requirements/requirements.txt

ENV PYTHONPATH=/app

ENTRYPOINT [ "python3", "./cert_scanner/scanner.py" ]