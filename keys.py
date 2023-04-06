import os, hashlib, base58
from curve import Point

class Keypair:
    def __init__(self, sk, pk, curve, G):
        self.sk = sk
        self.pk = pk
        self.curve = curve
        self.G = G
    
    def new(self):
        if self.sk == None:
            self.sk = self.new_private_key(32)
        self.pk = self.compute_public_key()
    
    def new_private_key(self, size):
        while True:
            sk = os.urandom(size)
            if int.from_bytes(sk, "big") < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                break
        sk_int = int(sk.hex(), 16)
        return sk_int
    
    def compute_public_key(self):
        if self.sk == None:
            return False
        pk = self.curve.double_and_add(self.sk, self.G)
        #pk_hex = hex(pk.x)[2:] + hex(pk.y)[2:]
        #self.pk_int = int(pk_hex, 16)
        return pk

def Secp256k1_new(curve):
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    G = Point(x,y)
    keypair = Keypair(None, None, curve, G)
    keypair.new()
    return keypair