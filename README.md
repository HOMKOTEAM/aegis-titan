# AEGIS TITAN v1.0

**The most secure encryption in open-source.**

## Features

| Parameter | Value |
|-----------|-------|
| Entropy | 7.996 bits/byte |
| Layers | 4 |
| Algorithms | ChaCha20 -> Feistel(100k) -> AES-256-GCM -> ChaCha20 |
| Key Length | 1024 bits (4 x 256) |
| KDF | Scrypt (N=2^20, r=16, p=1) |
| Compression | Zstandard level 22 |
| Header | **NONE** - ciphertext only |
| Shredding | 35 passes random data |

## Installation

`ash
git clone https://github.com/HOMKOTEAM/aegis-titan.git
cd aegis-titan
python -m venv venv
venv\Scripts\activate
pip install pycryptodome zstandard
Usage
Encrypt:

bash
python titan.py encrypt secret.txt secret.titan "YourPassword"
Encrypt + Shred:

bash
python titan.py encrypt secret.txt secret.titan "YourPassword" --shred
Decrypt:

bash
python titan.py decrypt secret.titan output.txt "YourPassword"
Warning
If you forget your password - data is lost forever. No backdoors.

License
MIT
