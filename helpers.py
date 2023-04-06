import os

def random_nonce():
    while True:
        sk = os.urandom(32)
        if int.from_bytes(sk, "little") < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            break
    return sk.hex()

# Unused
def compress_point(point):
    x, y = (point.x, point.y)
    sign = 0 if y >= 0 else 1
    y_abs = abs(y)
    x_bytes = x.to_bytes(32, byteorder='little')
    compressed_bytes = bytes([(sign << 7) | (y_abs >> i & 0x7f) for i in range(0, 256, 7)])
    return compressed_bytes[:32] + x_bytes