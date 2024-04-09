from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64


def pad_key(key: str):
    return key.encode("utf-8")[:24].ljust(24, b"\x00")


def encrypt(plaintext: str, key: str) -> str:
    padded_key = pad_key(key)
    iv = b"\x00" * 16  # 16 bytes of zeros for the IV
    backend = default_backend()
    cipher = Cipher(algorithms.AES(padded_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()


def decrypt(ciphertext: str, key: str) -> str:
    padded_key = pad_key(key)
    iv = b"\x00" * 16  # 16 bytes of zeros for the IV
    ciphertextBytes = base64.b64decode(ciphertext)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(padded_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(ciphertextBytes) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode()


def main():
    choice = input("Do you want to encrypt or decrypt? (e/d): ").lower()
    if choice not in ["e", "d"]:
        print("Invalid choice. Please enter 'e' to encrypt or 'd' to decrypt.")
        return

    if choice == "e":
        text = input("Enter the text: ")
    else:
        text = input("Enter the ciphertext in base 64: ")
    key = input("Enter the key: ")

    if choice == "e":
        encrypted_text = encrypt(text, key)
        print(f"Encrypted (Base64): {encrypted_text}")
    else:
        decrypted_text = decrypt(text, key)
        print(f"Decrypted: {decrypted_text}")


if __name__ == "__main__":
    main()
