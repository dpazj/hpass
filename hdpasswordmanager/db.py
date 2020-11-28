
import pathlib
import json
import os

from hdpasswordmanager.wallet import * 

class WalletDB(object): #not really a db but we will just call it that : ) 

    def __init__(self):
        home_path = str(pathlib.Path.home())
        self.db_path = home_path + "/.hdpasswordmanager/" 
        self.wallet_ext = ".wallet"

        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path)
            print("Created wallet directory: '{}'".format(self.db_path))

        self.wallet_names = self.get_wallets()

        
    def get_wallets(self):
        wallet_names = []
        for file in os.listdir(self.db_path):
            if file.endswith("*" + self.wallet_ext):
                wallet_names.append(file.split('.')[0]) 
        return wallet_names
    
    def wallet_file_exists(self, wallet_name):
        return os.path.isfile(self.get_wallet_path(wallet_name))


    def get_wallet_path(self, wallet_name):
        return self.db_path + wallet_name + self.wallet_ext 

#TODO add some error checking
    def load_wallet(self, wallet_name):
        if not self.wallet_file_exists:
            raise Exception("Wallet file doesnt exist!")
        with open(self.get_wallet_path(wallet_name)) as db:
            wallet = json.load(db)
        return wallet

    def update_wallet(self, wallet : PasswordWallet):
        wallet_name = wallet.name
        data = wallet.to_json()
        self.write_json_file(self.get_wallet_path(wallet_name), data)

    @staticmethod
    def write_json_file(path, data):
        with open(path, 'w') as db:
            json.dump(data, db)
    