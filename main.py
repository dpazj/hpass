from hdpasswordmanager.wallet import PasswordWallet
from hdpasswordmanager.db import WalletDB


db = WalletDB()


password_wallet, mnemonic = PasswordWallet.create_new_wallet()

print("Created new password wallet '{}'".format(password_wallet.name))
print("Your password wallet mneumonic is: \n\n{}\n\nPlease write this down somewhere safe, otherwise you will be unable to recover your wallet!\n".format(mnemonic))


password_wallet.add_account("jpaz@gmail.com")
password_wallet.add_account("jpaz@secretmail.com")


key, _ = password_wallet.create_password("jpaz@gmail.com","google.com")
print(password_wallet.to_json())

print("\n\n")

newkey, _ = password_wallet.update_password("jpaz@gmail.com", "google.com")
print(password_wallet.to_json())

password_wallet.delete_password("jpaz@gmail.com", "google.com")
print(password_wallet.to_json())


db.update_wallet(password_wallet)
print("Saved wallet '{}' to path {}".format(password_wallet.name, db.get_wallet_path(password_wallet.name)))

test = PasswordWallet.from_json(db.load_wallet("default"))
