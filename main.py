import argparse
from Crypto.Cipher import AES
import hashlib
import random
import string


def generate_password(min_length=12):
    valid_chars = string.ascii_letters + 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя' + string.digits + '+-/*'
    while True:
        password = ''.join(random.choice(valid_chars) for _ in range(min_length))
        if (any(c.isalpha() and c.islower() for c in password) and
            any(c.isalpha() and c.isupper() for c in password) and
            any(c in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя' for c in password) and
            any(c in '+-/*' for c in password) and
            any(c in '1234567890' for c in password) and
            all(password[i] != password[i+1] for i in range(len(password) - 1))):
            return password


def get_key_from_password(password):
    key = hashlib.sha256(password.encode()).digest()
    return key


def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(input_file, 'rb') as file_in:
        plaintext = file_in.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        with open(output_file, 'wb') as file_out:
            for x in (cipher.nonce, tag, ciphertext):
                file_out.write(x)


def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file_in:
        nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        with open(output_file, 'wb') as file_out:
            file_out.write(plaintext)


def main():
    parser = argparse.ArgumentParser(description='AES file encryption and decryption')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], nargs='?', help='Action: encrypt or decrypt')
    parser.add_argument('input_file', nargs='?', help='Input file name')
    parser.add_argument('output_file', nargs='?', help='Output file name')
    parser.add_argument('-p', '--password', help='Password for key generation')

    args = parser.parse_args()

    if not args.action or not args.input_file or not args.output_file:
        parser.print_help()
        return

    if not args.password:
        if args.action == 'encrypt':
            args.password = generate_password()
            print(f'Generated password: {args.password}')
        elif args.action == 'decrypt':
            print('Error: You need to specify a password (-p or --password)')
            return

    key = get_key_from_password(args.password)

    if args.action == 'encrypt':
        encrypt_file(args.input_file, args.output_file, key)
        print('File successfully encrypted!')
    elif args.action == 'decrypt':
        decrypt_file(args.input_file, args.output_file, key)
        print('File successfully decrypted!')


if __name__ == "__main__":
    main()
