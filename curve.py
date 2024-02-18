import hashlib, time
from helpers import random_nonce
from termcolor import colored

class Point:
    def __init__(self,x,y):
        self.x = x
        self.y = y
    def __str__(self):
        return str(self.x) + " - " + str(self.y)

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        
    def point_addition(self, P, Q):
        if P.x == None and P.y == None:
            return Q
        if Q.x == None and Q.y == None:
            return P
        x1, y1 = P.x, P.y
        x2, y2 = Q.x, Q.y

        if x1 == x2 and y1 == y2:
            m = ((3*x1*x1+self.a)%self.p * pow((2*y1)%self.p, self.p-2, self.p))%self.p
        else:
            m = ((y2-y1)%self.p * pow((x2-x1)%self.p, self.p-2,self.p))%self.p

        x3 = (m*m - x1 - x2)%self.p
        y3 = (m*(x1-x3) - y1)%self.p
        return Point(x3, y3)


    def double_and_add(self, n, P):
        if P.x == None and P.y == None:
            return P
        temp_point = Point(P.x, P.y)
        binary = bin(n)[2:]
        for binary_char in binary[1:]:
            # double
            temp_point = self.point_addition(temp_point, temp_point)
            if binary_char == '1':
                temp_point = self.point_addition(temp_point, P)
        return temp_point

class Secp256k1:
    def __init__(self):
        self.G = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        self.Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        self.p = 2**256 - 2**32 - 977
        self.n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        self.a = 0
        self.b = 7
        self.curve = EllipticCurve(self.a,self.b,self.p)
    
    def __str__(self):
        return f"G: {self.G}, p: {self.p}, n: {self.n}, a: {self.a}, b: {self.b}"
    
    def new(self, keypair, message):
        sk = keypair.sk
        A = keypair.pk
        r = int(random_nonce(), 16)
        R = self.curve.double_and_add(r, self.G)
        M = hashlib.sha512(message.encode('utf-8')).digest()
        R_bytes = R.x.to_bytes(32, byteorder='little') + R.y.to_bytes(32, byteorder='little')
        A_bytes = A.x.to_bytes(32, byteorder='little') + A.y.to_bytes(32, byteorder='little')
        H_R_A_M = hashlib.sha512(R.x.to_bytes(32, byteorder='little') + A.x.to_bytes(32, byteorder='little') + A.y.to_bytes(32, byteorder='little') + M).digest()
        H_R_A_M_int = int.from_bytes(H_R_A_M, byteorder='little') % self.n
        S = (r + H_R_A_M_int*sk) % self.n
        signature = self.curve.double_and_add(S, self.G)
        return {
            "message":message,
            "R":R,
            "A":A,
            "M":M,
            "H_R_A_M_int":H_R_A_M_int,
            "signature":signature
        }
    
    def verify(self, signature_json):
        R = signature_json["R"]
        A = signature_json["A"]
        M = signature_json["M"]
        H_R_A_M_int = signature_json["H_R_A_M_int"]
        # recompute H_R_A_M to verify that the signature is associated with the message hash.
        H_R_A_M_2 = hashlib.sha512(R.x.to_bytes(32, byteorder='little') + A.x.to_bytes(32, byteorder='little') + A.y.to_bytes(32, byteorder='little') + M).digest()
        H_R_A_M_2_int = int.from_bytes(H_R_A_M_2, byteorder='little') % self.n
        assert H_R_A_M_int == H_R_A_M_2_int

        sig = signature_json["signature"]
        signature = self.curve.point_addition(R, self.curve.double_and_add(H_R_A_M_int, A))
        assert signature.x == sig.x and signature.y == sig.y
        print(colored("Signature is valid.", "green"))

'''
R + H_R_A_M_int * A == (r + H_R_A_M_int * sk)%n * G
where R = r*G
and A = sk*G
'''

