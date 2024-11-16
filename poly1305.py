class Poly1305:

    P = 0x3fffffffffffffffffffffffffffffffb  # Modulo value (2^130 - 5)

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        
        # Split the key into r and s
        self.r = int.from_bytes(key[:16], byteorder='little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:], byteorder='little')
        self.acc = 0

    def create_tag(self, data):
        for i in range(0, len(data), 16):
            block = data[i:i+16]

            if len(block) < 16:
                block += b'\x01' + b'\x00' * (16 - len(block) - 1)

            n = int.from_bytes(block, byteorder='little')
            
            self.acc += n
            self.acc = (self.r * self.acc) % self.P
        
        self.acc += self.s
        self.acc %= self.P
        
        return self.acc.to_bytes(16, byteorder='little')

# key = b'\x01' * 32 
# data = b"Hello, Poly1305!"

# poly = Poly1305(key)
# tag = poly.create_tag(data)

# print("Authentication Tag:", tag.hex())
