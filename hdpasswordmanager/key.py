from hdpasswordmanager.mnemonic import Mnemonic
from hdpasswordmanager.utils import * 

from hashlib import sha256, sha512, pbkdf2_hmac


import hashlib
import hmac
import base58
import ecdsa


PASSWORD_PBKDF2_ITERATIONS = 100000

#http://www.secg.org/sec2-v2.pdf
secp256k1_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
secp256k1_a = 0
secp256k1_b = 7
secp256k1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
secp256k1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
secp256k1_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

secp256k1_curve = ecdsa.ellipticcurve.CurveFp(secp256k1_p, secp256k1_a, secp256k1_b)
secp256k1_gen = ecdsa.ellipticcurve.Point(secp256k1_curve, secp256k1_Gx, secp256k1_Gy, secp256k1_n)

class HDKey(object):

    def __init__(self, key : bytes, chain : bytes, is_public_key_only : bool = False, depth : int = 0, parent_fingerprint : bytes = b'\x00\x00\x00\x00', child_number : bytes = b'\x00\x00\x00\x00'):
        
        self.chain = chain
        self.depth = depth
        self.child_number = child_number
        self.parent_fingerprint = parent_fingerprint
        self.is_public_key_only = is_public_key_only


        #get pubkey info
        if is_public_key_only:
            self.privkey = None

            if len(key) == 65: #uncompressed key
                self.x = bytes_to_int(key[1:33])
                self.y = bytes_to_int(key[33:65])
            else: #we got a compressed key or just x
                if len(key) == 33:
                    key = key[1:32]
                self.x = bytes_to_int(key)
                
                #calculate y from x
                y = pow(self.x, 3, secp256k1_p) + 7 % secp256k1_p
                #square root of 'y' using the secp256k1 curve
                # k = secp256k1_p - 3 // 4
                k = 28948022309329048855892746252171976963317496166410141009864396001977208667915
                self.y = pow(y, k + 1, secp256k1_p)

        else: 
            self.privkey = key
            p = get_ec_point(key)

            self.x = p.x()
            self.y = p.y()
            

            
        if self.y % 2:
                prefix = b'\x03'
        else:
            prefix = b'\x02'

        self.pubkey_compressed = prefix + int_to_bytes(self.x,32)
        self.pubkey_uncompressed = b'\x04' + int_to_bytes(self.x, 32) + int_to_bytes(self.y, 32)
        
        
        self.key_identifier = hashlib.new('RIPEMD160', sha256(self.pubkey_compressed).digest()).digest()
        self.fingerprint = self.key_identifier[0:4]

    @staticmethod
    def from_seed(seed : bytes):
        #create the seed as per BIP_39
        I = hmac.new(b'Bitcoin seed', seed, sha512).digest()

        master_secret_key = I[:32]
        master_chain_code = I[32:64]

        master_secret_key_int = bytes_to_int(master_secret_key)
        if  master_secret_key_int >= secp256k1_n or master_secret_key_int == 0:
            raise Exception("Invalid Master Key Generation")
        
        return HDKey(key=master_secret_key, chain=master_chain_code)

    def get_key_password(self):
        if self.is_public_key_only:
            raise Exception("Key is public key only so cannot derive password")
        return bytes_to_base85(pbkdf2_hmac("sha512", self.privkey, self.chain, PASSWORD_PBKDF2_ITERATIONS)[:32])

    def get_child_number(self):
        return bytes_to_int(self.child_number)

    def get_key_identifier(self):
        return bytes_to_base58(self.key_identifier)

    def get_priv_wif(self):
        if self.is_public_key_only:
            raise Exception("Key is public_key_only!")
        return bytes_to_base58(self.serialize(False, self.privkey, self.chain, self.depth, self.parent_fingerprint, self.child_number))

    def get_pub_wif(self):
        return bytes_to_base58(self.serialize(True ,self.pubkey_compressed, self.chain, self.depth, self.parent_fingerprint, self.child_number))

    def derive_child_pubkey(self, index : int):
        if index >= 0x80000000:
            raise Exception("Cannot derive child pubkey from hardened public key, try another index!")

        child_number = int_to_bytes(index, 4)
        I = hmac.new(self.chain, self.pubkey_compressed + child_number, sha512).digest()
        
        Il = bytes_to_int(I[0:32])
        if Il >= secp256k1_n :
            raise Exception("Key greater than secp256k1_n, try another index!")


        child_key_point = get_ec_point(self.pubkey_compressed[1:]) + ecdsa.ellipticcurve.Point(secp256k1_curve, self.x, self.y, secp256k1_n)
        child_x = child_key_point.x()
        child_y = child_key_point.y()

        if child_y % 2:
            prefix = b'\x03'
        else:
            prefix = b'\x02'

        child_chain = I[32:64]
        child_key = prefix + int_to_bytes(child_x, 32)
        return HDKey(child_key, child_chain, is_public_key_only=True, depth = self.depth + 1, parent_fingerprint=self.fingerprint, child_number=child_number)

    def derive_child_privkey(self, index : int, hardened : bool = False):

        if self.privkey == None or self.is_public_key_only:
            raise Exception("Cannot derive child private key from public key")

        I = b''
        child_number = index
        
        if hardened:
            child_number += 0x80000000

        child_number_bytes = int_to_bytes(child_number, 4)


        if child_number >= 0x80000000:
            #hardened child
            I = hmac.new(self.chain, b'\x00' + self.privkey + child_number_bytes, sha512).digest()
        else:
            I = hmac.new(self.chain, self.pubkey_compressed + child_number_bytes, sha512).digest()

        child_secret_key_int = (bytes_to_int(I[:32]) + bytes_to_int(self.privkey)) % secp256k1_n

        child_secret_key = int_to_bytes(child_secret_key_int, 32)
        child_chain_code = I[32:64] 

        if child_secret_key_int >= secp256k1_n or child_secret_key_int == 0:
            raise Exception("Key greater than secp256k1_n, try another index")

        return HDKey(child_secret_key, child_chain_code, parent_fingerprint=self.fingerprint, child_number=child_number_bytes, depth=self.depth+1)

    @staticmethod
    def serialize(is_public_key : bool, key : bytes, chain : bytes, depth : int, parent_fingerprint : bytes, child_number : bytes):

        if not is_public_key:
            serialization_format = b'\x04\x88\xad\xe4'
        else: 
            serialization_format = b'\x04\x88\xb2\x1e' 

        serialization_format += int_to_bytes(depth,1) + parent_fingerprint + child_number
        serialization_format += chain

        if not is_public_key:
            serialization_format += b'\x00' + key
        else:
            serialization_format += key

        hash1 = sha256(serialization_format).digest()
        checksum = sha256(hash1).digest()
              
        serialization_format += checksum[0:4]
        
        return serialization_format
 
    @staticmethod
    def deserialize(data : bytes):
        magic = data[0:4]

        if magic == b'\x04\x88\xad\xe4':
            is_pub_key = False
        elif magic == b'\x04\x88\xb2\x1e':
            is_pub_key = True
        else:
            raise Exception("Unsupported key format!")

        depth = bytes_to_int(data[4:5])
        parent_fingerprint = data[5:9]
        child_number = data[9:13]
        chain = data[13:45]

        i = 78
        if not is_pub_key:
            key = data[46:78]

        else:
            key = data[45:77]
            i = 77
        
        checksum = data[i:i+4]
        testchecksum = sha256(sha256(data[0:-4]).digest()).digest()[0:4]

        if testchecksum != checksum:
            raise Exception("Invalid key checksum!")
 
        return HDKey(key=key, chain=chain, is_public_key_only=is_pub_key, depth=depth, parent_fingerprint=parent_fingerprint, child_number=child_number)

        

    @staticmethod
    def from_wif(wif : str):
        return HDKey.deserialize(base58_to_bytes(wif))       




#helper functions
def get_ec_point(privkey : bytes):
    return bytes_to_int(privkey) * secp256k1_gen  