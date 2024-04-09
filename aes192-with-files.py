from os import PathLike
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def get_key_from_user():
    key_input = input("Enter the key (will be padded or truncated to 24 bytes): ")
    return key_input[:24].ljust(24, "\x00")


def create_key_file_from_string(
    key_string: str, file_path: Union[str, PathLike[bytes]]
):
    with open(file_path, "wb") as key_file:
        key_file.write(key_string.encode("utf-8"))


def read_key_file(file_path: Union[str, PathLike[bytes]]) -> bytes:
    with open(file_path, "rb") as key_file:
        key = key_file.read()
        if len(key) != 24:
            raise ValueError("Key file is not exactly 24 bytes.")
        return key


def read_key_file_as_string(file_path: Union[str, PathLike[bytes]]):
    with open(file_path, "r", encoding="utf-8") as key_file:
        return key_file.read()


def encrypt(plaintext: str, key: bytes) -> bytes:
    iv = b"\x00" * 16  # 16 bytes of zeros for the IV
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def decrypt(ciphertext_file_path: Union[str, PathLike[bytes]], key: bytes) -> str:
    with open(ciphertext_file_path, "rb") as file:
        ciphertext = file.read()
    iv = b"\x00" * 16  # 16 bytes of zeros for the IV
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode()


def main():
    key_option = input(
        "Do you want to use an existing key file or create a new one? (e/n): "
    ).lower()
    if key_option == "n":
        key_string = get_key_from_user()
        key_file_path = input(
            "Enter the path to save the new key file (e.g. key-files/myKey.bin): "
        )
        create_key_file_from_string(key_string, key_file_path)
    elif key_option == "e":
        key_file_path = input(
            "Enter the path to the existing key file (e.g. key-files/myKey.bin): "
        )
    else:
        print("Invalid option. Please enter 'e' for existing or 'n' for new.")
        return

    try:
        key = read_key_file(key_file_path)
    except ValueError as e:
        print(e)
        return

    choice = input("Do you want to encrypt or decrypt? (e/d): ").lower()
    if choice not in ["e", "d"]:
        print("Invalid choice. Please enter 'e' to encrypt or 'd' to decrypt.")
        return

    if choice == "e":
        plaintext = input("Enter the plaintext: ")
        encrypted_data = encrypt(plaintext, key)
        output_file_path = input(
            "Enter the path to save the encrypted data (e.g. ciphertext-files/myCiphertext.bin): "
        )
        with open(output_file_path, "wb") as file:
            file.write(encrypted_data)
        print(f"Data encrypted and saved to {output_file_path}")
    else:
        ciphertext_file_path = input(
            "Enter the path to the ciphertext file (e.g. ciphertext-files/myCiphertext.bin): "
        )
        decrypted_text = decrypt(ciphertext_file_path, key)
        print(f"Decrypted text: {decrypted_text}")


if __name__ == "__main__":
    main()
