
from hdpasswordmanager.utils import *
from hdpasswordmanager.key import *


class PasswordWallet(object):

    def __init__(self, wallet_name : str, master_key : HDKey, accounts = None, keys = None, has_passphrase = False, account_index = 0):
        self.name = wallet_name
        self.master_key = master_key

        self.accounts = accounts
        self.account_index = account_index

        self.keys = keys
        self.has_passphrase = has_passphrase

        if self.accounts is None:
            self.accounts = {}
        if self.keys is None:
            self.keys = self.__populate_keys()


    def __populate_keys(self):
        keys = {}
        for account in self.accounts:
            a = 1
        return keys

    def get_account_names(self):
        return [x for x in self.accounts]

    def add_account(self, account_name):
        if account_name in self.accounts:
            return 

        self.account_index += 1
        try:
            account_key = self.master_key.derive_child_privkey(self.account_index)
        except:
            print("Invalid account key generated please try again!")
            return

        key_identifier = account_key.get_key_identifier()
        self.keys[key_identifier] = account_key

        #TODO maybe make a proper account object?
        self.accounts[account_name] = { 
            "key_identifier"    : key_identifier,
            "key_index" : 0,
            "services"  : {}        
        }  
        return 

    def to_json(self, export = False):

        data = {}
        data["wallet_name"] = self.name
        data["accounts"] = self.accounts
        data["account_index"] = self.account_index

        if not export: #we only want to include secrets if we are not exporting the wallet
            keys = {} 
            data["secrets"] = {}
            data["secrets"]["master_key"] = self.master_key.get_priv_wif()
            for key in self.keys:
                keys[key] = self.keys[key].get_priv_wif()
            data["secrets"]["keys"] = keys 

        return data

    @staticmethod
    def from_json(json):
        name = json["wallet_name"]
        accounts = json["accounts"]
        account_index = json["account_index"]
        #has_passphrase = json["has_passphrase"]
        secrets = json["secrets"]

        master_key = HDKey.from_wif(secrets["master_key"])
        keys = {}

        for key in secrets["keys"]:
            keys[key] = HDKey.from_wif(secrets["keys"][key])
             

        #if has_passphrase:
            #decrypt keys
        #    keys = keys

        return PasswordWallet(wallet_name=name, master_key=master_key, accounts=accounts, keys=keys, account_index=account_index) 
    
    @staticmethod
    def create_new_wallet(strength : int = 128, passphrase : str = "", wallet_name : str = "default"):
        #create new key

        mnemonic_gen = Mnemonic("english")
        mnemonic = mnemonic_gen.generate(strength)
        seed = mnemonic_gen.to_seed(mnemonic=mnemonic, passphrase=passphrase)

        master_key = HDKey.from_seed(seed)

        return PasswordWallet(wallet_name,master_key), mnemonic

    @staticmethod
    def from_export_file_(mneumonic, export_json):
        return
        







