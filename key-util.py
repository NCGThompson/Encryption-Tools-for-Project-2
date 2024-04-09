import base64
import string


def create_key():
    format_choice = input(
        "Is the key in (1) UTF-8, (2) Hexadecimal, or (3) Base64? Enter 1, 2, or 3: "
    )
    key_input = input("Enter the key: ")
    output_file_path = input(
        "Enter the path to save the encrypted data (e.g. key-files/myKey.bin): "
    )

    if format_choice == "1":  # UTF-8
        key_bytes = key_input.encode("utf-8")[:24].ljust(24, b"\x00")
    elif format_choice == "2":  # Hexadecimal
        if len(key_input) != 48:
            print("Invalid Hexadecimal length. It must be 48 characters long.")
            return
        key_bytes = bytes.fromhex(key_input)
    elif format_choice == "3":  # Base64
        key_bytes = base64.b64decode(key_input)
        if len(key_bytes) != 24:
            print("Invalid Base64 decoding. The decoded length must be 24 bytes.")
            return
    else:
        print("Invalid choice.")
        return

    with open(output_file_path, "wb") as file:
        file.write(key_bytes)
    print("Key file created successfully.")


def read_key():
    key_input = input("Enter the key's path (e.g. key-files/myKey.bin): ")
    try:
        with open(key_input, "rb") as file:
            key_bytes = file.read()
    except FileNotFoundError:
        print("Key file not found.")
        return

    if len(key_bytes) != 24:
        print("Invalid key file size. It must be exactly 24 bytes.")
        return

    can_reproduce, utf8_string = can_reproduce_from_utf8(key_bytes)

    hex_string = key_bytes.hex()
    base64_string = base64.b64encode(key_bytes).decode("utf-8")

    print(f"UTF-8 Interpretation: {utf8_string}")
    print(f"Hexadecimal: {hex_string}")
    print(f"Base64: {base64_string}")
    print(f"Can be reproduced from UTF-8 string: {'Yes' if can_reproduce else 'No'}")


def can_reproduce_from_utf8(key_bytes: bytes):
    # Define printable characters (excluding control characters like null byte)
    printable_chars = bytes(string.printable, "utf-8")

    # Filter only printable characters from the key
    printable_key_bytes = bytes(filter(lambda x: x in printable_chars, key_bytes))

    try:
        # Decode only the printable part of the key
        utf8_string = printable_key_bytes.decode("utf-8")
        # Canonicalize by re-encoding the decoded string back to bytes
        canonical_bytes = utf8_string.encode("utf-8")
        # Compare the canonical form to the printable part of the original bytes
        return canonical_bytes == printable_key_bytes, utf8_string
    except UnicodeDecodeError:
        return False, "Cannot be decoded to a UTF-8 string."


def main():
    choice = input("Do you want to (1) create or (2) read a key file? Enter 1 or 2: ")
    if choice == "1":
        create_key()
    elif choice == "2":
        read_key()
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
