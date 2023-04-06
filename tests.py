from termcolor import colored
import hashlib, time

from helpers import random_nonce, compress_point
from curve import Point, Secp256k1
from keys import Secp256k1_new

def test_sign_and_verify():
    # optional: re-use existing keypair
    secp256k1 = Secp256k1()
    keypair = Secp256k1_new(secp256k1.curve)
    signature_json = secp256k1.new(keypair, "Jonas und Kristiana luv much")
    secp256k1.verify(signature_json)
test_sign_and_verify()
