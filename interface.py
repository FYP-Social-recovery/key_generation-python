import bip39 
import random
from bip32 import BIP32, HARDENED_INDEX
from tkinter import *
from tkinter import ttk

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

#generate the Entropy
def generateEntropy():
    randomNumber = random.getrandbits(128)
    print("Random number ",randomNumber)
    return randomNumber
#Entropy as bytes
def entropyAsBytes(randomNumber):
    entropy= bitstring_to_bytes(bin(randomNumber))
    return entropy

##generate mnemonic words 
def generateMnemonic(entropy):
    mnemonic =bip39.encode_bytes(entropy)
    return mnemonic

#generate 512 bit seed
def generateBitSeed(mnemonicPhrase):
    seed= bip39.phrase_to_seed(mnemonicPhrase)
    return seed

#generate seed using the mnemonic 
def regenerateEntropy(mnemonic):
    decoded_phrase= bip39.decode_phrase(mnemonic)
    return decoded_phrase

def createBIP32(seed):
    bip32 = BIP32.from_seed(seed)
    return bip32

def getExtendedPrivateKEyFromPath(bip32,path="m/44'/0'/0'"):
    extendedPrivateKey=bip32.get_xpriv_from_path(path)
    return extendedPrivateKey

def getExtendedPublicKeyFromPath(bip32,path="m/44'/0'/0'"):
    publicKey= bip32.get_pubkey_from_path(path)
    return publicKey 
 

root = Tk()
frm = ttk.Frame(root, padding=20)
frm.grid()
ttk.Label(frm, text="Experiment").grid( row=0)
ttk.Button(frm, text="Generate Entropy", command=generateEntropy).grid(column=0, row=1)
ttk.Button(frm, text="Generate Mnemonic", command=generateEntropy).grid(column=0, row=2)
ttk.Button(frm, text="Generate seed", command=generateEntropy).grid(column=0, row=3)
ttk.Button(frm, text="Generate Extended Privatekey", command=generateEntropy).grid(column=0, row=4)
ttk.Button(frm, text="Generate Extended Public Key", command=generateEntropy).grid(column=0, row=5)
ttk.Button(frm, text="Generate Private Key", command=generateEntropy).grid(column=0, row=6)
ttk.Button(frm, text="Generate Entropy From The Mnemonic", command=generateEntropy).grid(column=0, row=7)
ttk.Button(frm, text="Generate Public Key", command=generateEntropy).grid(column=0, row=8)
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=2)
root.mainloop()
