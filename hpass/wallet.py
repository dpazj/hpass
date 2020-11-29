
from utils import *
from key import *


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
            account = self.accounts[account]
            account_key = self.master_key.derive_child_privkey(account["account_index"])
            if account["key_identifier"] != account_key.get_key_identifier():
                raise Exception("Invalid key identifier, it is likely the master key is incorrect")
            keys[account_key.get_key_identifier()] = account_key

            for service in account["services"]:
                service = account["services"][service]
                service_key = account_key.derive_child_privkey(service["key_index"])
                if service["key_identifier"] != service_key.get_key_identifier():
                    raise Exception("Invalid key identifier, wallet file is corrupted")
                keys[service_key.get_key_identifier()] = service_key
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
            return self.add_account(account_name)

        key_identifier = account_key.get_key_identifier()
        self.keys[key_identifier] = account_key

        #TODO maybe make a proper account object?
        self.accounts[account_name] = { 
            "key_identifier"    : key_identifier,
            "key_index" : 0,
            "account_index" : self.account_index,
            "services"  : {}        
        }  
        return account_key, key_identifier

    def create_password(self, account_name, service):
        if account_name not in self.accounts:
            self.add_account(account_name)
          
        ki = self.accounts[account_name]["key_identifier"]
        account_key = self.keys[ki]

        self.accounts[account_name]["key_index"] += 1

        key_index = self.accounts[account_name]["key_index"]
        try:
            new_pass_key = account_key.derive_child_privkey(key_index)
        except:
            return self.create_password(account_name, service) #we recursively call create password until a valid key is found
        new_key_identifier = new_pass_key.get_key_identifier()

        self.accounts[account_name]["services"][service] = {"key_identifier" : new_key_identifier, "key_index" : key_index} 
        self.keys[new_key_identifier] = new_pass_key
        return new_pass_key, new_key_identifier 

    def get_password(self, account_name, service):
        ki = self.get_key_identifier(account_name, service)
        if ki is None:
            return
        return self.keys[ki].get_key_password().decode("utf-8")

    def get_key_identifier(self, account_name, service):
        if account_name not in self.accounts:
            return
        services = self.accounts[account_name]["services"]
        
        if service not in services: 
            return
        ki = services[service]["key_identifier"] 
        return ki

    def update_password(self, account_name, service):
        ki = self.get_key_identifier(account_name, service)
        if ki is None:
            return
        del self.keys[ki]
        return self.create_password(account_name, service)

    def delete_password(self, account_name, service):
        ki = self.get_key_identifier(account_name, service)
        if ki is None: 
            return
        del self.keys[ki]

    def to_json(self, export = False):

        data = {}
        data["wallet_name"] = self.name
        data["accounts"] = self.accounts
        data["account_index"] = self.account_index
        data["export"] = export

        if not export: #we only want to include secrets if we are not exporting the wallet
            keys = {} 
            data["secrets"] = {}
            data["secrets"]["master_key"] = self.master_key.get_priv_wif()
            for key in self.keys:
                keys[key] = self.keys[key].get_priv_wif()
            data["secrets"]["keys"] = keys 
        return data

    @staticmethod
    def from_json(json, import_master_key : HDKey = None):
        name = json["wallet_name"]
        accounts = json["accounts"]
        account_index = json["account_index"]
        export = json["export"]

        if export:
            master_key = import_master_key
            keys = None 
        else:
            secrets = json["secrets"]
            master_key = HDKey.from_wif(secrets["master_key"])
            keys = {}

            for key in secrets["keys"]:
                keys[key] = HDKey.from_wif(secrets["keys"][key])
             
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
    def from_export_file(export_json, mnemonic, passphrase=""):
        mnemonic_gen = Mnemonic("english")
        seed = mnemonic_gen.to_seed(mnemonic=mnemonic, passphrase=passphrase)
        master_key = HDKey.from_seed(seed) 
        return PasswordWallet.from_json(export_json, master_key)
        