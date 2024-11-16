from chacha import ChaCha
from poly1305 import Poly1305

class ChaChaPoly:
    def __init__(self, key):
        """
        Initialize the ChaChaPoly instance.

        :param key: A 256-bit (32-byte) secret key.
        """
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes).")
        self.key = key

    def encrypt_and_authenticate(self, plaintext, nonce):
        """
        Encrypts the plaintext and generates a MAC for authentication.

        :param plaintext: The plaintext message to encrypt (bytes).
        :param nonce: A 96-bit (12-byte) unique nonce (must be used only once).
        :return: A tuple containing (ciphertext, MAC tag).
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bits (12 bytes).")

        # Encrypt using ChaCha
        chacha = ChaCha(self.key, nonce)
        ciphertext = chacha.encrypt(plaintext)

        # Generate MAC tag using Poly1305
        poly1305 = Poly1305(self.key)
        tag = poly1305.create_tag(ciphertext)

        return ciphertext, tag

    def decrypt_and_verify(self, ciphertext, nonce, tag):
        """
        Decrypts the ciphertext and verifies the MAC tag.

        :param ciphertext: The encrypted message (bytes).
        :param nonce: The 96-bit (12-byte) nonce used during encryption.
        :param tag: The 16-byte MAC tag for authentication.
        :return: The decrypted plaintext if the tag is valid.
        :raises ValueError: If the MAC tag verification fails.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bits (12 bytes).")
        if len(tag) != 16:
            raise ValueError("Tag must be 128 bits (16 bytes).")

        # Verify MAC tag using Poly1305
        poly1305 = Poly1305(self.key)
        calculated_tag = poly1305.create_tag(ciphertext)

        if calculated_tag != tag:
            raise ValueError("Authentication failed: Invalid MAC tag.")

        # Decrypt using ChaCha
        chacha = ChaCha(self.key, nonce)
        plaintext = chacha.decrypt(ciphertext)

        return plaintext
