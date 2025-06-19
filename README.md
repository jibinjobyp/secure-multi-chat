# Secure Multi-User Encrypted Chat

A simple multi-user chat application in Python with **end-to-end RSA encryption** for secure messaging.  
Built with Python sockets and a Tkinter GUI. No database needed.

---

## Features

- User authentication by username (no password)
- RSA key pair generation and storage per user
- Public key exchange via server for encryption
- Encrypted messaging between selected users only
- Real-time online users list
- Simple and minimal GUI

---

## Requirements

- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)
- Tkinter (usually included with Python)

Install dependencies with:

```bash
pip install -r requirements.txt
