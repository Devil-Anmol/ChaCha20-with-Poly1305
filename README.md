# **ChaCha20-Poly1305 Encryption & Decryption Tool**

This project demonstrates the use of the **ChaCha20-Poly1305** encryption scheme to securely encrypt and decrypt data. It allows users to input a plaintext message, a 256-bit key (32 bytes), and a 96-bit nonce (12 bytes) to generate an encrypted ciphertext and a Message Authentication Code (MAC) tag. The tool also verifies the ciphertext's authenticity during decryption.

---

## **Features**
- **Secure Encryption:** Utilizes the ChaCha20 stream cipher combined with the Poly1305 MAC for authenticated encryption.
- **Interactive Inputs:** Accepts user-provided keys, nonces, and plaintext for flexibility.
- **Default Values:** Provides default key and nonce values for ease of use in testing.
- **Error Handling:** Validates inputs and catches decryption errors to ensure data integrity.
- **User-Friendly Interface:** Simple script that can run directly in a terminal or command prompt.

---

## **How It Works**
1. **Encryption:**
   - The plaintext is encrypted using the ChaCha20 cipher.
   - A MAC tag is generated using Poly1305 to ensure the ciphertext's authenticity.
2. **Decryption:**
   - The ciphertext is decrypted.
   - The MAC tag is verified to ensure the message hasn’t been tampered with.
3. **Inputs and Outputs:**
   - **Inputs:** Key (32 bytes), Nonce (12 bytes), Plaintext.
   - **Outputs:** Ciphertext (hexadecimal) and MAC Tag (hexadecimal).

---

## **Installation**
### **Requirements**
- Python 3.x

### **Steps**
1. Clone the repository:
   ```bash
   git clone https://github.com/Devil-Anmol/ChaCha20-with-Poly1305.git
   cd ChaCha20-with-Poly1305
   ```
2. Run the script:
   ```bash
   python main.py
   ```

---

## **Usage**
1. Run the script:
   ```bash
   python main.py
   ```
2. Follow the prompts:
   - Enter a **32-byte key** in hexadecimal format or press **Enter** to use the default key.
   - Enter a **12-byte nonce** in hexadecimal format or press **Enter** to use the default nonce.
   - Enter the plaintext message to encrypt.
3. View the encryption results (ciphertext and MAC tag) and the decrypted message.

---

## **Sample Output**

```plaintext
=== ChaCha20-Poly1305 Encryption & Decryption ===
Enter a 32-byte key in hexadecimal format (or press Enter to use default): 
Enter a 12-byte nonce in hexadecimal format (or press Enter to use default): 
Enter the plaintext message to encrypt: Hello, secure world!

=== Encryption Results ===
Ciphertext (hex): 3edd8cc1cfdd1de3253e1f9736a... (shortened for example)
MAC Tag (hex): 00000000000000000...

=== Decryption Results ===
Decrypted Message: Hello, secure world
```

---

## **Use Cases**
1. **Secure Communications:**
   - Encrypt sensitive messages for transmission over insecure networks.
   - Verify message integrity with the MAC tag.

2. **Data Protection:**
   - Securely encrypt files or sensitive data before storing them in a database or on disk.

3. **Learning Cryptography:**
   - Understand the practical implementation of authenticated encryption using ChaCha20-Poly1305.

4. **Building Security Applications:**
   - Use this script as a starting point for implementing ChaCha20-Poly1305 encryption in larger projects.

---
