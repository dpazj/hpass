
from hdpasswordmanager.utils import *
from hdpasswordmanager.key import *
from hdpasswordmanager.db import WalletDB


class PasswordWallet(object):

    def __init__(self, wallet_name : str, master_key : HDKey, accounts = None, keys = None, has_passphrase = False):
        self.name = wallet_name
        self.master_key = master_key
        self.accounts = accounts 
        self.keys = keys
        self.has_passphrase = has_passphrase

        if self.keys is None:
            self.keys = self.__populate_keys()
        if self.accounts is None:
            self.accounts = {}

    def __populate_keys(self):
        keys = {}
        for account in self.accounts:
            a = 1
        return keys

    def to_json(self, export = False):

        data = {}
        data["wallet_name"] = self.name
        data["accounts"] = self.accounts

        if not export:
            keys = []
            keys.append(self.master_key.get_priv_wif())

            for key in self.keys:
                keys.append(key.get_priv_wif())
            data["key"] = keys 



        return {}

    @staticmethod
    def from_json(json):
        name = json["wallet_name"]
        accounts = json["accounts"]
        keys = json["keys"]
        has_passphrase = json["has_passphrase"]

        if has_passphrase:
            #decrypt keys
            keys = keys

        return PasswordWallet(wallet_name=name, master_key=master_key, accounts=accounts, keys=keys, has_passphrase=has_passphrase) 
    
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
        








