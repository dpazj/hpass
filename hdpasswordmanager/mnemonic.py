import os
import unicodedata

from hashlib import sha256, sha512, pbkdf2_hmac



VALID_STRENGTH = [128,160,192,224,256]
SUPPORTED_LANGUAGES = ["english"]
PBKDF2_ITERATIONS = 2048


#implemented as described https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#Generating_the_mnemonic

class Mnemonic(object):
    def __init__(self, language : str):
        if language not in SUPPORTED_LANGUAGES:
            raise Exception("Unsupported Language")
        with open(os.path.join(os.path.dirname(__file__), "wordlists/") + language + ".txt") as f:
            self.wordlist = f.read().splitlines()
        

    
    def generate(self, strength : int):
        if strength not in VALID_STRENGTH:
            raise Exception("Invalid strength value, must be either [128, 160, 192, 224, 256] bits")
        
        return self.create_mnemonic(os.urandom(strength//8))


    def create_mnemonic(self, entropy : bytes):
        if len(entropy) * 8 not in VALID_STRENGTH:
            raise Exception("Entropy must be [16, 20, 24, 28, 32] bytes")
        
        checksum = sha256(entropy).digest()

        checksum_length = (len(entropy) * 8) // 32    

        entropy = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
        checksum = bin(int.from_bytes(checksum, "big"))[2:].zfill(256)
      
        entropy_checksum = entropy + checksum[:checksum_length]
        #split into chunks of size 11 
        chunks = [entropy_checksum[i:i+11] for i in range(0,len(entropy_checksum),11)]

        return " ".join([self.wordlist[int(x,2)] for x in chunks])

    def to_seed(self, mnemonic : str, passphrase : str = ""):
        passphrase = unicodedata.normalize("NFKD",passphrase)
        mnemonic = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
        password = ("mnemonic" + passphrase).encode("utf-8")
        
        return pbkdf2_hmac("sha512", mnemonic, password, PBKDF2_ITERATIONS)




