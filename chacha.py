import struct

class ChaCha:

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    _round_mixup_box = [(0, 4, 8, 12),
                    (1, 5, 9, 13),
                    (2, 6, 10, 14),
                    (3, 7, 11, 15),
                    (0, 5, 10, 15),
                    (1, 6, 11, 12),
                    (2, 7, 8, 13),
                    (3, 4, 9, 14)]

    @staticmethod
    def rotl32(v, c):
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 16) & 0xffffffff | (xd >> 16))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 12) & 0xffffffff | (xb >> 20))

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 8) & 0xffffffff | (xd >> 24))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 7) & 0xffffffff | (xb >> 25))

        x[a] = xa
        x[b] = xb
        x[c] = xc
        x[d] = xd

    @classmethod
    def double_round(cls, x):
        for a, b, c, d in cls._round_mixup_box:
            xa = x[a]
            xb = x[b]
            xc = x[c]
            xd = x[d]

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 16) & 0xffffffff | (xd >> 16))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 12) & 0xffffffff | (xb >> 20))

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 8) & 0xffffffff | (xd >> 24))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 7) & 0xffffffff | (xb >> 25))

            x[a] = xa
            x[b] = xb
            x[c] = xc
            x[d] = xd

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        state = ChaCha.constants + key + [counter] + nonce

        working_state = state[:]
        dbl_round = ChaCha.double_round
        for _ in range(0, rounds // 2):
            dbl_round(working_state)

        return [(st + wrkSt) & 0xffffffff for st, wrkSt in zip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        return bytearray(struct.pack('<' + 'L' * len(state), *state))

    @staticmethod
    def _bytearray_to_words(data):
        ret = []
        for i in range(0, len(data)//4):
            ret.extend(struct.unpack('<L', data[i*4:(i+1)*4]))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bits (12 bytes)")

        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)
        self.counter = counter
        self.rounds = rounds

    def encrypt(self, plaintext):
        encrypted_message = bytearray()
        for i, block in enumerate(plaintext[i:i+64] for i in range(0, len(plaintext), 64)):
            key_stream = self.key_stream(i)
            encrypted_message += bytearray(x ^ y for x, y in zip(key_stream, block))

        return encrypted_message

    def key_stream(self, counter):
        key_stream = ChaCha.chacha_block(self.key, self.counter + counter, self.nonce, self.rounds)
        key_stream = ChaCha.word_to_bytearray(key_stream)
        return key_stream

    def decrypt(self, ciphertext):
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