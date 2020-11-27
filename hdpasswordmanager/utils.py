import struct 
import base58
import base64

def bytes_to_int(x : bytes, byteorder : str = "big", signed=False):
    return int.from_bytes(x, byteorder,signed=signed)

def int_to_bytes(x : int, length : int, byteorder : str ="big", signed=False):
    return x.to_bytes(length, byteorder, signed=signed)

def int_to_hex(x : int):
    return hex(x)[2:]

def hex_to_bytes(x : str):
    return bytes.fromhex(x)

def bytes_to_hex(x : bytes):
    return x.hex()

def str_to_bytes(x : str):
    return str.encode(x)

def base58_to_bytes(x : str):
    return base58.b58decode(x)

def bytes_to_base58(x : bytes):
    return base58.b58encode(x).decode("utf-8")


def bytes_to_base85(x : bytes):
    return base64.a85encode(x)



    