from hdpasswordmanager.wallet import PasswordWallet
from hdpasswordmanager.db import WalletDB


db = WalletDB()


def create():
    print("Create!")
    return 
 
def ls():
    wallet_names = db.get_wallet_names()
    if len(wallet_names == 0):
        print("No wallets found!")
    else:
        for name in wallet_names: 
            print(name)