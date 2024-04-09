# Encryption Utility

Interactive Python scripts to help you verify your CSCI 485 Project 3 decryption code

We were told that the target file will be encrypted with the equivalent of the algorithm found at https://encode-decode.com/aes192-encrypt-online/. After some testing, I determined that it uses the [CBC block mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)) with an initialization vector of all zeroes. The plaintext message is padded to be a multiple of 24 bytes (128 bits) following the [PKCS#7 standard](https://youtu.be/iZe_q3qW1cE).

* [`aes192-encrypt-online.py`](aes192-encrypt-online.py) is intended to emulate the website. This is so that you can see exactly what it is doing by examining the python source code, and so you can verify that the code here is correct.
* [`aes192-with-files.py`](aes192-with-files.py) instead uses paths to binary files for keys and ciphertexts in the same format that `secret_file.txt` and `special_file.txt` will be in for Project 2.
* [`key-util.py`](key-util.py) can create a key file from a string using the same algorithm as the website, or read the file. It also supports hexadecimal and [base 64 4648](https://en.wikipedia.org/wiki/Base64#Base64_table_from_RFC_4648).

## Installation

The only dependency is the `cryptography` python package which can be installed with one of:
``` ssh
pip3 install cryptography
```
``` ssh
pip3 install -r requirements.txt
```
``` ssh
conda --file requirements.txt
```
``` ssh
mamba --file requirements.txt
```

You may want to start a virtual environment ([`.venv`](https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/) or [`.conda`](https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html#creating-an-environment-with-commands)) first.

## Contributing

If you want to make edits, it is also recommended to install the dependencies from `dev-requirements.txt` as well.

If you are using VS Code, you do not need to install or manually use pyright as long as you have the suggested extensions installed, but you should still manually run `ruff check` and `ruff format`. You may be interested in [creating virtual environments](https://code.visualstudio.com/docs/python/environments#_creating-environments).

As an alternative to `ruff` you can use [`black`](https://pypi.org/project/black/) and [`pyflakes`](https://pypi.org/project/pyflakes/), which `ruff` is intended to emulate.

This work is dual-licensed under [Apache 2.0](LICENSE-APACHE.txt) and [MIT](LICENSE-APACHE.txt). You can choose between one of them if you use this work.
