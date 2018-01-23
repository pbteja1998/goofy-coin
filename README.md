# GoofyCoin

## About

This project mainly uses

* [Python 2.7](https://www.python.org/) - A widely used high-level programming language for general-purpose programming.
* [PyCrypto](https://pypi.python.org/pypi/pycrypto) - Cryptographic modules for Python.

### Prerequisites

1. [Python](https://www.python.org)

   * Version 2.7

   ```bash
   # To check python version
   python -V
   ```

1. [VirtualEnv](https://virtualenv.pypa.io/en/stable/)

   * Installing instructions are at [official docs](https://virtualenv.pypa.io/en/stable/installation/).

#### Running Locally

1. Fork the [repository](https://github.com/pbteja1998/goofy-coin).
1. Then clone your forked repository
   ```bash
    git clone <your forked repository url>
   ```
1. Move to the repository's root folder
   ```bash
    cd goofy-coin
   ```
1. Create a virtual environment
   ```bash
    virtualenv -p python venv
   ```
1. Activate venv
   ```bash
    source venv/bin/activate
   ```
1. Install the requirements
   ```bash
    pip install -r requirements.txt
   ```
1. Run the Code
   ```bash
    python base.py
   ```

### Implementation
  To check the implementation details, check [this](Implementation.md)