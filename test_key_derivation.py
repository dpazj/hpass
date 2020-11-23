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

        assert current_key.get_priv_wif() == str_to_bytes(keys[0]["extpriv"])
        assert current_key.get_pub_wif() == str_to_bytes(keys[0]["extpub"])

        for x in range(1, len(keys)):
            is_hardened = keys[x]["hardened"]
            child_index = keys[x]["child_index"]
            current_key = current_key.derive_child_privkey(child_index, is_hardened)

            # print(current_key.get_priv_wif())
            # print(str_to_bytes(keys[x]["extpriv"]))

            # print( current_key.get_pub_wif())
            # print(str_to_bytes(keys[x]["extpub"]))

            assert current_key.get_priv_wif() == str_to_bytes(keys[x]["extpriv"]), keys[x]["key"]
            assert current_key.get_pub_wif() == str_to_bytes(keys[x]["extpub"])
    print("Key derivation tests: PASSED\n")

            
        

test_key_derivation()