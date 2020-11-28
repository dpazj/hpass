from hdpasswordmanager.wallet import PasswordWallet
from hdpasswordmanager.db import WalletDB


db = WalletDB()


password_wallet, mnemonic = PasswordWallet.create_new_wallet()

print("Created new password wallet '{}'".format(password_wallet.name))
print("Your password wallet mneumonic is: \n\n{}\n\nPlease write this down somewhere safe, otherwise you will be unable to recover your wallet!\n".format(mnemonic))


password_wallet.add_account("jpaz@gmail.com")
password_wallet.add_account("jpaz@secretmail.com")


key, _ = password_wallet.create_password("jpaz@gmail.com","google.com")
newkey, _ = password_wallet.update_password("jpaz@gmail.com", "google.com")
key, _ = password_wallet.create_password("jpaz@gmail.com", "youtube.com")

export_file = password_wallet.to_json(True)


import_wallet = PasswordWallet.from_export_file(export_file, mnemonic)

print(import_wallet.to_json() == password_wallet.to_json())



