from wallet import PasswordWallet
from db import WalletDB
from mnemonic import VALID_STRENGTH


db = WalletDB()


def get_input(message, default=None, is_int = False, valid_list = None, valid_list_msg=None, invalid_list = None, invalid_list_msg=None):
    valid = False 
    inpt = " "

    if valid_list_msg is None and valid_list is not None:
        valid_list_msg = "Input is not valid. must be in [{}]".format(" ".join(str(x) for x in valid_list))
    if invalid_list_msg is None and invalid_list is not None:
        invalid_list_msg = "Input is not valid. It cannot be in [{}]".format(" ".join(str(x) for x in invalid_list))

    while(not valid):
        inpt = input(message)

        valid = True

        if default is not None and len(inpt) == 0:
            inpt = default 


        if invalid_list is not None and inpt in invalid_list and valid:
            valid = False
            print(invalid_list_msg)    

        if is_int and valid:
            try:
                inpt = int(inpt)
            except ValueError:
                print("Input is not an integer!")
                valid = False
        
        if valid_list is not None and inpt not in valid_list and valid:
            valid = False
            print(valid_list_msg)

    return inpt

            
def create():
    name = get_input("Enter your wallet name: (Default) ", default="Default", invalid_list=db.get_wallet_names(), invalid_list_msg="Wallet name already exists!")
    
    print("(OPTIONAL) You can add a passphrase to make your password wallet more secure. Leave blank for no passphrase.")
    passphrase = get_input("Enter your wallet passphrase: ")

    print("Valid wallet strengths are {}".format(" ".join(str(x) for x in VALID_STRENGTH)))
    strength = get_input("Enter your wallet strength: (128) ", default=128, is_int=True, valid_list=VALID_STRENGTH)
    
    new_wallet, mneumonic = PasswordWallet.create_new_wallet(wallet_name=name, strength=strength, passphrase=passphrase)

    db.update_wallet(new_wallet)
    
    print("\nCreated new wallet '{}'\nYour password wallet mneumonic is:\n\n{}\n\nPlease write this down somewhere safe as it can be used to recover your wallet!".format(new_wallet.name, mneumonic))

def delete():
    name = get_input("Enter the name of the wallet you wish to delete: ", valid_list=db.get_wallet_names(), valid_list_msg="Wallet does not exist")

    confirm = get_input("To confirm the deletion of wallet '{}' please re-enter the wallets name: ".format(name), valid_list=[name], valid_list_msg="Confirmation check failed!")

    if confirm == name:
        db.delete_wallet(name)
        print("Deleted wallet '{}'".format(name))
    
def ls():
    wallet_names = db.get_wallet_names()
    if len(wallet_names) == 0:
        print("No wallets found!")
    else:
        for name in wallet_names: 
            print(name)