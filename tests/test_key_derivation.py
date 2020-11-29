import json
import os

from hdpasswordmanager.key import HDKey
from hdpasswordmanager.utils import * 

def test_key_derivation():
    cur_path = os.path.dirname(__file__)
    new_path = os.path.relpath('test_vectors/bip0032-test_vec.json', cur_path)
   
    with open(new_path) as f:
        test_vectors = json.load(f)
    

    for x in test_vectors:
        print("Performing test vector: {}".format(x))
        vector = test_vectors[x]
        seed = hex_to_bytes(vector['seed'])
        
        current_key = HDKey.from_seed(seed)

        keys = vector['keys']

        assert current_key.get_priv_wif() == keys[0]["extpriv"]
        assert current_key.get_pub_wif() == keys[0]["extpub"]

        for x in range(1, len(keys)):
            is_hardened = keys[x]["hardened"]
            child_index = keys[x]["child_index"]
            current_key = current_key.derive_child_privkey(child_index, is_hardened)

            # print(current_key.get_priv_wif())
            # print(str_to_bytes(keys[x]["extpriv"]))

            # print( current_key.get_pub_wif())
            # print(str_to_bytes(keys[x]["extpub"]))

            assert current_key.get_priv_wif() == keys[x]["extpriv"], keys[x]["key"]
            assert current_key.get_pub_wif() == keys[x]["extpub"]
    print("Key derivation tests: PASSED\n")


def test_key_serialization_deserialization():
    print ("Testing key serialization deserialization")
    priv_wif = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

    hdkey = HDKey.from_wif(priv_wif)

    assert priv_wif == hdkey.get_priv_wif()

    print("Key serialization deserialization: PASSED")

            
        

test_key_derivation()
test_key_serialization_deserialization()