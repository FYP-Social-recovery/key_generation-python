import bip39 
import random
from coincurve import PrivateKey
from bip44 import Wallet
from bip44.utils import get_eth_addr
from bip32 import BIP32, HARDENED_INDEX
from tkinter import *
from tkinter import ttk

#generate the random value 

def generateEntropy():
    randomNumber = random.getrandbits(128)
    print("Random number ",randomNumber)
    entropy= bitstring_to_bytes(bin(randomNumber))
    print("Entropy: ",entropy)
    return entropy



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



#generate mnemonic words 
def generateMnemonic(entropy):
    mnemonic =bip39.encode_bytes(entropy)
    return mnemonic




#generate 512 bit seed
def generateBitSeed(mnemonicPhrase):
    seed= bip39.phrase_to_seed(mnemonicPhrase)
    print("512 bit seed::",byte_to_bit(seed))
    return seed
# seed= bip39.phrase_to_seed(mnemonic)



#generate seed using the mnemonic 
def regenerateEntropy(mnemonic):
    decoded_phrase= bip39.decode_phrase(mnemonic)
    print("regenerated entropy using the mnemonic",decoded_phrase)
    return decoded_phrase


# #generate entropy using the mnemonic
# entropy= bip39.get_entropy_bits(12)
# print(entropy)

def createBIP32(seed):
    bip32 = BIP32.from_seed(seed)
    return bip32


# print(hex(int(byte_to_bit(bip32.privkey))))


# extendedPrivateKey=bip32.get_xpriv_from_path("m/44'/0'/0'")
# print("Extended private key: ",extendedPrivateKey)

# privateKey= bip32.get_privkey_from_path("m/44'/0'/0'")
# print("Private key of the given path: ",hex(int(byte_to_bit(privateKey),2)))

# publicKey= bip32.get_pubkey_from_path("m/44'/0'/0'")
# print("public key of the given path: ",hex(int(byte_to_bit(publicKey),2)))
def getExtendedPrivateKEyFromPath(bip32,path="m/44'/0'/0'"):
    extendedPrivateKey=bip32.get_xpriv_from_path(path)
    print("Extended Private Key",extendedPrivateKey)
    return extendedPrivateKey

def getPublicKeyFromPath(bip32,path="m/44'/0'/0'"):
    publicKey= bip32.get_pubkey_from_path(path)
    print("public key of the given path: ",path,hex(int(byte_to_bit(publicKey),2)))
    return publicKey 
 

def main():
    entropy=generateEntropy()
    mnemonic=generateMnemonic(entropy)
    seed=generateBitSeed(mnemonic)    
    regeneratedEntropy=regenerateEntropy(mnemonic)
    bip32 =createBIP32(seed)
    xprv=getExtendedPrivateKEyFromPath(bip32,"m/44'/0'/0'")
    
    pub=getPublicKeyFromPath(bip32,"m/44'/0'/0'")
    


    return

# main()


root = Tk()
frm = ttk.Frame(root, padding=20)
frm.grid()
ttk.Label(frm, text="Experiment").grid( row=0)
ttk.Button(frm, text="Generate Entropy", command=main).grid(column=0, row=1)
# ttk.Button(frm, text="Generate Mnemonic", command=generateEntropy).grid(column=0, row=2)
# ttk.Button(frm, text="Generate seed", command=generateEntropy).grid(column=0, row=3)
# ttk.Button(frm, text="Generate Extended Privatekey", command=generateEntropy).grid(column=0, row=4)
# ttk.Button(frm, text="Generate Extended Public Key", command=generateEntropy).grid(column=0, row=5)
# ttk.Button(frm, text="Generate Private Key", command=generateEntropy).grid(column=0, row=6)
# ttk.Button(frm, text="Generate Entropy From The Mnemonic", command=generateEntropy).grid(column=0, row=7)
# ttk.Button(frm, text="Generate Public Key", command=generateEntropy).grid(column=0, row=8)
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=2)
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





