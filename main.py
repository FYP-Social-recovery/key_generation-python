import bip39 
import random
from coincurve import PrivateKey
from bip44 import Wallet
from bip44.utils import get_eth_addr
from bip32 import BIP32, HARDENED_INDEX


#generate the random value 
randomNumber = random.getrandbits(128)
print("Random number ",randomNumber)

#convert the random value into byte array
def bitstring_to_bytes(s):
    v = int(s, 2)
    bytes_arr = bytearray()
    while v:
        bytes_arr.append(v & 0xff)
        v >>= 8
    return bytes(bytes_arr[::-1])


def access_bit(data, num):
    base = int(num // 8)
    shift = int(num % 8)
    return (data[base] >> shift) & 0x1

def byte_to_bit(seed):
    bitSeed=""
    for i in range(len(seed)*8):
        bitSeed=bitSeed+str(access_bit(seed,i))
    return bitSeed


entropy= bitstring_to_bytes(bin(randomNumber))

print("entropy in byte array:::",entropy)
#generate mnemonic words 
mnemonic =bip39.encode_bytes(entropy)
print(type(mnemonic))
print("mnemonic-words:::",mnemonic)

#generate 512 bit seed
seed= bip39.phrase_to_seed(mnemonic)

print("512 bit seed::",byte_to_bit(seed))

#generate seed using the mnemonic 
decoded_phrase= bip39.decode_phrase(mnemonic)
print("regenerated entropy using the mnemonic",decoded_phrase)

# #generate entropy using the mnemonic
# entropy= bip39.get_entropy_bits(12)
# print(entropy)

bip32 = BIP32.from_seed(seed)
print(hex(int(byte_to_bit(bip32.privkey))))


extendedPrivateKey=bip32.get_xpriv_from_path("m/44'/0'/0'")
print("Extended private key: ",extendedPrivateKey)

privateKey= bip32.get_privkey_from_path("m/44'/0'/0'")
print("Private key of the given path: ",hex(int(byte_to_bit(privateKey),2)))

publicKey= bip32.get_pubkey_from_path("m/44'/0'/0'")
print("public key of the given path: ",hex(int(byte_to_bit(publicKey),2)))

from tkinter import *
from tkinter import ttk
root = Tk()
frm = ttk.Frame(root, padding=10)
frm.grid()
ttk.Label(frm, text="Hello World!").grid(column=0, row=0)
ttk.Button(frm, text="Generate Entropy", command=root.destroy).grid(column=1, row=1)
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=0)
root.mainloop()




# passphrase=""
# w=Wallet(mnemonic,"english",passphrase)
# sk, pk = w.derive_account("eth", account=0)
# # sk = PrivateKey(sk) 
# privateKey=hex(int(byte_to_bit(sk), 2))
# publicKey=hex(int(byte_to_bit(pk), 2))
# print("private key of the wallet ",privateKey)
# print("public key of the wallet",publicKey)

# address= get_eth_addr(pk)
# print(address)





