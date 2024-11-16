import os
from chachapoly1305 import ChaChaPoly

# Generate a 256-bit key and a 96-bit nonce
key = b'\x00' * 32
nonce = b'\x00' * 11 + b'\x01'
plaintext = b"Helloo!!"

# Create a ChaChaPoly instance
secure = ChaChaPoly(key)

# Encrypt and authenticate
ciphertext, tag = secure.encrypt_and_authenticate(plaintext, nonce)
print("Ciphertext:", ciphertext.hex())
print("MAC Tag:", tag.hex())

# Decrypt and verify
try:
    decrypted_message = secure.decrypt_and_verify(ciphertext, nonce, tag)
    print("Decrypted Message:", decrypted_message.decode())
except ValueError as e:
    print("Error:", str(e))

