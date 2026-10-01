# Homework 2: Protect Agent Messages with Classic Cryptography

## Environment setup

Requires Ubuntu with Python 3.12 and OpenSSL 3.0 or newer.

Install Python virtual environment support:

```bash
sudo apt update
sudo apt install python3.12-venv
```

From the repository root, create and activate the virtual environment:

```bash
cd hw2
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

The DH group parameters are provided in `ffdhe3072.pem`. If the file is missing, generate it from inside `hw2/`:

```bash
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

For subsequent terminal sessions, activate the existing environment from the repository root:

```bash
cd hw2
source .venv/bin/activate
```

To leave the virtual environment:

```bash
deactivate
```