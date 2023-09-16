

---

## AES File Encryption and Decryption

This Python program offers a simple command-line interface for encrypting and decrypting files using the Advanced Encryption Standard (AES) algorithm. It utilizes the pycryptodome library for cryptographic operations.

### Features:

- **Encryption and Decryption**: Encrypt and decrypt files securely using AES encryption.
- **Password-Based Key Generation**: You can either specify a password or let the program generate a strong password for key generation.
- **Password Requirements**: The generated password adheres to certain requirements, including the presence of lowercase and uppercase letters, digits, special characters, and the absence of consecutive identical characters.
- **Support for Various Character Sets**: The program supports multiple character sets, including Latin, Cyrillic, digits, and common arithmetic operators.

### Usage:

#### Encryption:
```shell
python main.py encrypt input.txt encrypted.bin -p your_password
```

#### Decryption:
```shell
python main.py decrypt encrypted.bin decrypted.txt -p your_password
```

If no password is provided during encryption, the program will generate a password for you and display it. For decryption, you must specify the password used during encryption.

### Getting Started:

1. Clone this repository.
2. Ensure you have Python and the required libraries installed.
3. Run the program as described above.

This program can help you secure your sensitive files with AES encryption. Enjoy using it!

---

Feel free to customize this description as needed for your GitHub repository.