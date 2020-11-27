from hdpasswordmanager.mnemonic import Mnemonic
import json
import os
def test_mnemonic():
    cur_path = os.path.dirname(__file__)
    new_path = os.path.relpath('test_vectors/mnemonic-testvec.json', cur_path)
   
    with open(new_path) as f:
        test_vectors = json.load(f)
    passphrase = "TREZOR"
    mnemonic_obj = Mnemonic("english")

    test_vectors = test_vectors["test_vectors"]
    for test in test_vectors:
        entropy = bytes.fromhex(test[0])
        mnemonic = test[1]
        seed = bytes.fromhex(test[2])
       
        assert mnemonic_obj.create_mnemonic(entropy) == mnemonic
        assert mnemonic_obj.to_seed(mnemonic,passphrase) == seed
    print("Test vectors passed")



#test vectors taken from
#https://github.com/trezor/python-mnemonic/blob/master/vectors.json

test_mnemonic()