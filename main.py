import os
from chachapoly1305 import ChaChaPoly

def main():
    print("=== ChaCha20-Poly1305 Encryption & Decryption ===")

    # Input for key
    key = input("Enter a 32-byte key in hexadecimal format (or press Enter to use default): ").strip()
    if not key:
        key = b'\x00' * 32  # Default key
    else:
        try:
            key = bytes.fromhex(key)
            if len(key) != 32:
                raise ValueError("Key must be exactly 32 bytes.")
        except ValueError as e:
            print("Invalid key format:", str(e))
            return

    # Input for nonce
    nonce = input("Enter a 12-byte nonce in hexadecimal format (or press Enter to use default): ").strip()
    if not nonce:
        nonce = b'\x00' * 12  # Default nonce
    else:
        try:
            nonce = bytes.fromhex(nonce)
            if len(nonce) != 12:
                raise ValueError("Nonce must be exactly 12 bytes.")
        except ValueError as e:
            print("Invalid nonce format:", str(e))
            return

    # Input for plaintext
    plaintext = input("Enter the plaintext message to encrypt: ").encode()

    # Initialize the ChaCha20-Poly1305 instance
    secure = ChaChaPoly(key)

    # Encrypt the plaintext and compute the authentication tag
    ciphertext, tag = secure.encrypt_and_authenticate(plaintext, nonce)
    print("\n=== Encryption Results ===")
    print("Ciphertext (hex):", ciphertext.hex())
    print("MAC Tag (hex):", tag.hex())

    # Attempt decryption
    try:
        decrypted_message = secure.decrypt_and_verify(ciphertext, nonce, tag)
        print("\n=== Decryption Results ===")
        print("Decrypted Message:", decrypted_message.decode())
    except ValueError as e:
        print("\nDecryption failed. Error:", str(e))

if __name__ == "__main__":
    main()
