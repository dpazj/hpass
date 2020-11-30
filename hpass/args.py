from wallet import PasswordWallet
from db import WalletDB
from mnemonic import VALID_STRENGTH

import argparse
import pyperclip

def parse():
    parser = argparse.ArgumentParser()
    parser.set_defaults(func= lambda x: parser.print_usage()) 
    subparsers = parser.add_subparsers(help='sub-command help')

    #Create command
    create_parser = subparsers.add_parser('create', help='Create help here')
    create_parser.add_argument('name', type=str, help='Name of your wallet')
    create_parser.add_argument('-s', '--strength', type=int, default=128)
    create_parser.add_argument('-p', '--passphrase', type=str, default="")
    create_parser.set_defaults(func=create)

    #ls command
    ls_parser = subparsers.add_parser('ls', help='List help here')
    ls_parser.set_defaults(func=ls)

    #delete command
    delete_parser = subparsers.add_parser('delete', help='Delete help here')
    delete_parser.add_argument('name', type=str, help='Name of the wallet you wish to delete.')
    delete_parser.add_argument('--force', '-f', dest='force', action='store_true', default=False)
    delete_parser.set_defaults(func=delete)

    #export command

    #import command

    #add command
    add_parser = subparsers.add_parser('add', help='Add help here')
    add_parser.add_argument('wallet', type=str, help="Name of wallet")
    add_parser.add_argument('username', type=str, help="Username you wish to create a password for")
    add_parser.add_argument('service', type=str, help="Service you wish to create a password for")
    add_parser.set_defaults(func=add)

    #get command 
    get_parser = subparsers.add_parser('get', help = 'Get help here')
    get_parser.add_argument('wallet', type=str, help="Name of wallet")
    get_parser.add_argument('username', type=str, help="Username you wish to get the password of")
    get_parser.add_argument('service', type=str, help="Service you wish to get the password of")
    get_parser.set_defaults(func=get)

    #update command 
    update_parser = subparsers.add_parser('update', help="Update help here")
    update_parser.add_argument('wallet', type=str, help="Name of wallet")
    update_parser.add_argument('username', type=str, help="Username you wish to get the password of")
    update_parser.add_argument('service', type=str, help="Service you wish to get the password of")
    update_parser.set_defaults(func=update)

    args = parser.parse_args()
    args.func(args)

def open_wallet(db, name):
    if name not in db.get_wallet_names():
        print("Wallet '{}' does not exist!".format(name))
        return None

    wallet = PasswordWallet.from_json(db.load_wallet(name))
    return wallet

def update(args):
    wallet_name = args.wallet
    service = args.service
    username = args.username

    db = WalletDB()
    wallet = open_wallet(db, wallet_name)
    if wallet is None:
        return

    if not wallet.update_password(username, service):
        print("Wallet {}: Could not update the password for username '{}' and service '{}'. Do they exist?!".format(wallet_name, username, service))
        return 
    
    db.update_wallet(wallet)
    print("Wallet {}: Updated password for username '{}' and service '{}'".format(wallet_name, username, service))

def get(args):
    wallet_name = args.wallet
    service = args.service
    username = args.username

    db = WalletDB()
    wallet = open_wallet(db, wallet_name)
    if wallet is None:
        return
    
    password = wallet.get_password(username, service)

    if password is None:
        print("Wallet {}: Could not get the password for username '{}' and service '{}'. Do they exist?!".format(wallet_name, username, service))
        return 

    pyperclip.copy(password)
    print("Password copied to clipboard!")



def add(args):
    wallet_name = args.wallet
    username = args.username
    service = args.service

    db = WalletDB()
    wallet = open_wallet(db, wallet_name)
    if wallet is None: 
        return 

    success = wallet.add_service(username, service)

    if not success:
        print("Wallet '{}': Could not create a password for service :'{}', as one already exists!".format(wallet_name, service))
        return  

    db.update_wallet(wallet)
    print("Wallet '{}': Created password for service '{}'.".format(wallet_name, service))


def delete(args):
    force = args.force
    name = args.name

    db = WalletDB()
    if name not in db.get_wallet_names():
        print("Wallet '{}' does not exist!".format(name))
        return

    if not force:
        confirm = input("To confirm the deletion of wallet '{}' please re-enter the wallets name: ".format(name))
        if confirm != name:
            print("Wallet name and confirmation answer does not match!")
            return 
    db.delete_wallet(name)
    print("Deleted wallet '{}'".format(name))
        


def create(args):
    name = args.name
    strength = args.strength
    passphrase = args.passphrase

    db = WalletDB()

    if name in db.get_wallet_names():
       print("Wallet name already exists!")
       return
    if strength not in VALID_STRENGTH:
           print("Valid wallet strengths are {}".format(" ".join(str(x) for x in VALID_STRENGTH)))
           return

    new_wallet, mneumonic = PasswordWallet.create_new_wallet(wallet_name=name, strength=strength, passphrase=passphrase)

    db.update_wallet(new_wallet)
    
    print("Created new wallet '{}'\nYour password wallet mneumonic is:\n\n{}\n\nPlease write this down somewhere safe as it can be used to recover your wallet!".format(new_wallet.name, mneumonic))

def ls(args):
    db = WalletDB()
    wallet_names = db.get_wallet_names()
    if len(wallet_names) == 0:
        print("No wallets found!")
    else:
        for name in wallet_names: 
            print(name)

parse()