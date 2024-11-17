class Poly1305:

    # The modulo value used in the Poly1305 MAC algorithm (2^130 - 5)
    P = 0x3fffffffffffffffffffffffffffffffb

    def __init__(self, key):
        """
        Initialize the Poly1305 object with a 256-bit key.
        The key is split into two parts: r (16 bytes) and s (16 bytes).
        """
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")  # Validate key length
        
        # Split the key into two 128-bit values: r and s
        # r will be used in the internal multiplication, and s is added at the end
        self.r = int.from_bytes(key[:16], byteorder='little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:], byteorder='little')
        self.acc = 0  # Initialize the accumulator

    def create_tag(self, data):
        """
        Create an authentication tag for the given data using Poly1305.
        The data is processed in 16-byte blocks, and padding is added if the last block is shorter than 16 bytes.
        """
        # Iterate over the data in 16-byte chunks
        for i in range(0, len(data), 16):
            block = data[i:i+16]  # Get the next 16-byte block

            # If the block is smaller than 16 bytes, pad it with 0x01 followed by 0x00
            if len(block) < 16:
                block += b'\x01' + b'\x00' * (16 - len(block) - 1)

            # Convert the block to an integer (little-endian byte order)
            n = int.from_bytes(block, byteorder='little')
            
            # Update the accumulator with the current block
            self.acc += n
            # Multiply the accumulator by r, and take modulo P
            self.acc = (self.r * self.acc) % self.P
        
        # Add the constant s to the accumulator, and take modulo P
        self.acc += self.s
        self.acc %= self.P
        self.acc &= (1 << 128) - 1
        
        # Return the result as a 16-byte authentication tag
        return self.acc.to_bytes(16, byteorder='little')

# # Example usage:
# key = b'\x01' * 32  # Example 256-bit key
# data = b"Hello, Poly1305!"  # Example data to authenticate

# poly = Poly1305(key)  # Initialize the Poly1305 object with the key
# tag = poly.create_tag(data)  # Create the authentication tag for the data

# print("Authentication Tag:", tag.hex())  # Print the tag in hexadecimal format
