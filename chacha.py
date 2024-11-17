import struct

class ChaCha:

    # Constants used in the ChaCha algorithm, derived from the string "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    # Round mixup box defines how the state words will be mixed in each round
    _round_mixup_box = [
        (0, 4, 8, 12),  # Round 1
        (1, 5, 9, 13),  # Round 2
        (2, 6, 10, 14), # Round 3
        (3, 7, 11, 15), # Round 4
        (0, 5, 10, 15), # Round 5
        (1, 6, 11, 12), # Round 6
        (2, 7, 8, 13),  # Round 7
        (3, 4, 9, 14)   # Round 8
    ]

    @staticmethod
    def rotl32(v, c):
        """
        Rotate the 32-bit integer `v` left by `c` positions.
        :param v: 32-bit integer
        :param c: number of positions to rotate
        :return: rotated 32-bit integer
        """
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """
        Perform a single quarter-round operation on the state array.
        :param x: state array
        :param a, b, c, d: indices of the words to operate on
        """
        # Extract values at the indices
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        # First operation: xa = (xa + xb) and update xd
        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 16) & 0xffffffff | (xd >> 16))

        # Second operation: xc = (xc + xd) and update xb
        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 12) & 0xffffffff | (xb >> 20))

        # Third operation: xa = (xa + xb) and update xd
        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 8) & 0xffffffff | (xd >> 24))

        # Final operation: xc = (xc + xd) and update xb
        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 7) & 0xffffffff | (xb >> 25))

        # Write the results back into the state array
        x[a] = xa
        x[b] = xb
        x[c] = xc
        x[d] = xd

    @classmethod
    def double_round(cls, x):
        """
        Perform 8 rounds of the ChaCha algorithm on the state array.
        :param x: state array
        """
        for a, b, c, d in cls._round_mixup_box:
            # Perform quarter-round for each mixup box
            cls.quarter_round(x, a, b, c, d)

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """
        Generate a single block of the ChaCha stream cipher.
        :param key: 256-bit key (32 bytes)
        :param counter: counter value
        :param nonce: 96-bit nonce (12 bytes)
        :param rounds: number of rounds to apply
        :return: ChaCha block (list of 16 words, each 32-bits)
        """
        # Initial state is the constant array, key, counter, and nonce
        state = ChaCha.constants + key + [counter] + nonce

        # Copy the state for manipulation
        working_state = state[:]
        
        # Perform rounds of the ChaCha algorithm
        for _ in range(0, rounds // 2):
            ChaCha.double_round(working_state)

        # Combine the initial state with the working state and return the result
        return [(st + wrkSt) & 0xffffffff for st, wrkSt in zip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        """
        Convert a list of 32-bit words to a bytearray.
        :param state: list of 32-bit words
        :return: bytearray representing the state
        """
        return bytearray(struct.pack('<' + 'L' * len(state), *state))

    @staticmethod
    def _bytearray_to_words(data):
        """
        Convert a bytearray to a list of 32-bit words.
        :param data: bytearray to convert
        :return: list of 32-bit words
        """
        ret = []
        for i in range(0, len(data)//4):
            ret.extend(struct.unpack('<L', data[i*4:(i+1)*4]))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        """
        Initialize the ChaCha object with key, nonce, counter, and rounds.
        :param key: 256-bit key (32 bytes)
        :param nonce: 96-bit nonce (12 bytes)
        :param counter: initial counter value
        :param rounds: number of rounds for ChaCha (default is 20)
        """
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bits (12 bytes)")

        # Convert key and nonce to 32-bit words
        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)
        self.counter = counter
        self.rounds = rounds

    def encrypt(self, plaintext):
        """
        Encrypt the plaintext using ChaCha20.
        :param plaintext: byte string to encrypt
        :return: encrypted byte string
        """
        encrypted_message = bytearray()
        
        # Encrypt the plaintext in 64-byte blocks
        for i, block in enumerate(plaintext[i:i+64] for i in range(0, len(plaintext), 64)):
            key_stream = self.key_stream(i)
            encrypted_message += bytearray(x ^ y for x, y in zip(key_stream, block))

        return encrypted_message

    def key_stream(self, counter):
        """
        Generate the key stream for a given counter value.
        :param counter: counter value for the key stream generation
        :return: key stream as a bytearray
        """
        key_stream = ChaCha.chacha_block(self.key, self.counter + counter, self.nonce, self.rounds)
        key_stream = ChaCha.word_to_bytearray(key_stream)
        return key_stream

    def decrypt(self, ciphertext):
        """
        Decrypt the ciphertext using ChaCha20 (same as encryption).
        :param ciphertext: byte string to decrypt
        :return: decrypted byte string
        """
        return self.encrypt(ciphertext)

# key = b'\x00' * 32
# nonce = b'\x00' * 12
# counter = 1
# plaintext = b"Hello, ChaCha20 Encryption"

# cipher = ChaCha(key, nonce)

# ciphertext = cipher.encrypt(plaintext)
# print("Ciphertext:", ciphertext.hex())

# decrypted = cipher.decrypt(ciphertext)
# print("Decrypted:", decrypted.decode())
