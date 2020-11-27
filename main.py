from hdpasswordmanager.wallet import PasswordWallet
from hdpasswordmanager.db import WalletDB


db = WalletDB()


password_wallet, mnemonic = PasswordWallet.create_new_wallet()

print("Created new password wallet '{}'".format(password_wallet.name))
print("Your password wallet mneumonic is: \n\n{}\n\nPlease write this down somewhere safe, otherwise you will be unable to recover your wallet!\n".format(mnemonic))


password_wallet.add_account("jpaz@gmail.com")
password_wallet.add_account("jpaz@secretmail.com")


db.update_wallet(password_wallet)
print("Saved wallet '{}' to path {}".format(password_wallet.name, db.get_wallet_path(password_wallet.name)))



test = PasswordWallet.from_json(db.load_wallet("default"))


print(test.get_account_names())


