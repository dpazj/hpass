from hdpasswordmanager.wallet import PasswordWallet
from hdpasswordmanager.db import WalletDB


db = WalletDB()


password_wallet, mnemonic = PasswordWallet.create_new_wallet()

print("Created new password wallet '{}'".format(password_wallet.name))
print("Your password wallet mneumonic is: \n\n{}\n\nPlease write this down somewhere safe, otherwise you will be unable to recover your wallet".format(mnemonic))


