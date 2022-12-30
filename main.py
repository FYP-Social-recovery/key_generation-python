import bip39 
import random
from coincurve import PrivateKey
from bip44 import Wallet
from bip44.utils import get_eth_addr
from bip32 import BIP32, HARDENED_INDEX
from tkinter import *
from tkinter import ttk
import tkinter as tk

#generate the random value 

def generateEntropy():
    randomNumber = random.getrandbits(128)
    print("Random number ",randomNumber)
    entropy= bitstring_to_bytes(bin(randomNumber))
    print("Entropy: ",entropy)
    return entropy



#convert functions (bit to byteArray and byteArray to bit) 
def bitstring_to_bytes(s):
    print(s)
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
    print("mnemonic:",mnemonic)
    return mnemonic





#generate 512 bit seed
def generateBitSeed(mnemonicPhrase,password):
    seed= bip39.phrase_to_seed(mnemonicPhrase,password)
    print("512 bit seed as a byte array: ",seed)
    print("512 bit seed::",byte_to_bit(seed))
    return seed
# seed= bip39.phrase_to_seed(mnemonic)



#generate seed using the mnemonic 
def regenerateEntropy(mnemonic):
    decoded_phrase= bip39.decode_phrase(mnemonic)
    print("regenerated entropy using the mnemonic",decoded_phrase)
    return decoded_phrase




#create BIP32 object
def createBIP32(seed):
    bip32 = BIP32.from_seed(seed)
    return bip32


#create extended private keys and public keys for the default path
def getExtendedPrivateKEyFromPath(bip32,path="m/44'/0'/0'"):
    extendedPrivateKey=bip32.get_xpriv_from_path(path)
    print("Extended Private Key",extendedPrivateKey)
    return extendedPrivateKey

def getExtendedPublicKeyFromPath(bip32,path="m/44'/0'/0'"):
    extendedPublicKey= bip32.get_xpub_from_path(path)
    print("Extended Private Key",extendedPublicKey)
    return extendedPublicKey 
 
#create public keys and the private keys for a given path 
def getPublicKeyFromPath(bip32,path="m/44'/60'/0'/0/0"):
    publicKey= bip32.get_pubkey_from_path(path)
    print("public key of the given path: ",path,hex(int(byte_to_bit(publicKey),2)))
    publicKeyHex=hex(int(byte_to_bit(publicKey),2))
    return publicKeyHex

def getPrivateKeyFromPath(bip32,path="m/44'/60'/0'/0/0"):
    privateKey=bip32.get_privkey_from_path(path)
    print("Private key of the given path: ",path,hex(int(byte_to_bit(privateKey),2)))
    privateKeyHex=hex(int(byte_to_bit(privateKey),2))
    return privateKeyHex




def main(password=""):
    entropy=generateEntropy()
    mnemonic=generateMnemonic(entropy)
    seed=generateBitSeed(mnemonic,password)    
    regeneratedEntropy=regenerateEntropy(mnemonic) #not used for now just for testing
    bip32 =createBIP32(seed)
    xprv=getExtendedPrivateKEyFromPath(bip32,"m/44'/0'/0'")
    xpub=getExtendedPublicKeyFromPath(bip32,"m/44'/0'/0'")
    
    prv1=getPrivateKeyFromPath(bip32,"m/44'/60'/0'/0/0")
    pub1=getPublicKeyFromPath(bip32,"m/44'/60'/0'/0/0")

    prv2=getPrivateKeyFromPath(bip32,"m/44'/0'/0'/1")
    pub2=getPublicKeyFromPath(bip32,"m/44'/0'/0'/1")

    prv3=getPrivateKeyFromPath(bip32,"m/44'/0'/0'/2")
    pub3=getPublicKeyFromPath(bip32,"m/44'/0'/0'/2")

    # prv4=getPrivateKeyFromPath(bip32,"m/44'/60'/0'/0/0")
    # pub4=getPublicKeyFromPath(bip32,"m/44'/60'/0'/0/0")

    return entropy,mnemonic,seed,bip32,xprv,xpub,prv1,pub1,prv2,pub2,prv3,pub3




root= tk.Tk()

canvas1 = tk.Canvas(root, width=1500, height=700, relief='raised')
canvas1.pack()

label1 = tk.Label(root, text='Generating Private keys')
label1.config(font=('helvetica', 14))
canvas1.create_window(200, 25, window=label1)

label2 = tk.Label(root, text='Type your Password :')
label2.config(font=('helvetica', 10))
canvas1.create_window(50, 100,anchor=W,window=label2)

entry1 = tk.Entry(root) 
canvas1.create_window(250, 100, window=entry1)

#result viewer
def viewer(bitEntropy,mnemonic,bitSeed,bip32,xprv,xpub,prv1,pub1,prv2,pub2,prv3,pub3):
    label3 = tk.Label(root, text='The entropy ' + ' is:', font=('helvetica', 10))
    canvas1.create_window(50, 250,anchor=W, window=label3)
   
    label4 = tk.Label(root, text=bitEntropy, font=('helvetica', 10, 'bold'))
    canvas1.create_window(100, 250,width=1450,anchor=W, window=label4)

    label5 = tk.Label(root, text='Mnemonic Phrase: ', font=('helvetica', 10))
    canvas1.create_window(50, 300,anchor=W, window=label5)

    label6 = tk.Label(root, text=mnemonic, font=('helvetica', 10, 'bold'))
    canvas1.create_window(200, 300,width=550,anchor=W, window=label6)

    label7 = tk.Label(root, text='----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------', font=('helvetica', 10))
    canvas1.create_window(50, 350,anchor=W, window=label7)

    # label7 = tk.Label(root, text='Seed: ', font=('helvetica', 10))
    # canvas1.create_window(50, 350,anchor=W, window=label7)
    
    # label8 = tk.Label(root, text=bitSeed, font=('helvetica', 10, 'bold'))
    # canvas1.create_window(150, 350,width=1450,anchor=W, window=label8)

    label9 = tk.Label(root, text='Extended Private key: ', font=('helvetica', 10))
    canvas1.create_window(50, 400,anchor=W, window=label9)
    
    label10 = tk.Label(root, text=xprv, font=('helvetica', 10, 'bold'))
    canvas1.create_window(100, 400,width=1400,anchor=W, window=label10)

    label11 = tk.Label(root, text='Extended Public key: ', font=('helvetica', 10))
    canvas1.create_window(50, 450,anchor=W, window=label11)
    
    label12 = tk.Label(root, text=xpub, font=('helvetica', 10, 'bold'))
    canvas1.create_window(100, 450,width=1400,anchor=W, window=label12)

    # private key for the m/44/0/0/0 path 

    label13 = tk.Label(root, text="Private key for m/44'/0'/0'/0: ", font=('helvetica', 10))
    canvas1.create_window(50, 500,anchor=W, window=label13)
    
    label14 = tk.Label(root, text=prv1, font=('helvetica', 10, 'bold'))
    canvas1.create_window(250, 500,width=800,anchor=W, window=label14)
    #public key for the m/44/0/0/0 path 
    label15 = tk.Label(root, text="Public key for m/44'/0'/0'/0: ", font=('helvetica', 10))
    canvas1.create_window(50, 550,anchor=W, window=label15)
    
    label16 = tk.Label(root, text=pub1, font=('helvetica', 10, 'bold'))
    canvas1.create_window(250, 550,width=800,anchor=W, window=label16)

    #private key for the m/44/0/0/1 path 

    label17 = tk.Label(root, text="Private key for m/44'/0'/0'/1: ", font=('helvetica', 10))
    canvas1.create_window(50, 600,anchor=W, window=label17)
    
    label18 = tk.Label(root, text=prv2, font=('helvetica', 10, 'bold'))
    canvas1.create_window(250, 600,width=800,anchor=W, window=label18)
    #public key for the m/44/0/0/1 path 
    label18 = tk.Label(root, text="Public key for m/44'/0'/0'/1: ", font=('helvetica', 10))
    canvas1.create_window(50, 650,anchor=W, window=label18)
    
    label20 = tk.Label(root, text=pub2, font=('helvetica', 10, 'bold'))
    canvas1.create_window(250, 650,width=800,anchor=W, window=label20)

    #private key for the m/44/0/0/2 path 

    label21 = tk.Label(root, text="Private key for m/44'/0'/0'/2: ", font=('helvetica', 10))
    canvas1.create_window(50, 700,anchor=W, window=label21)
    
    label22 = tk.Label(root, text=prv3, font=('helvetica', 10, 'bold'))
    canvas1.create_window(250, 700,width=800,anchor=W, window=label22)
    #public key for the m/44/0/0/2 path 
    label23 = tk.Label(root, text="Public key for m/44'/0'/0'/2: ", font=('helvetica', 10))
    canvas1.create_window(50, 750,anchor=W, window=label23)
    
    label24 = tk.Label(root, text=pub3, font=('helvetica', 10, 'bold'))
    canvas1.create_window(250, 750,width=800,anchor=W, window=label24)
    return


# After the button click 
def compute():
    clean()
    value = entry1.get()
    
    entropy,mnemonic,seed,bip32,xprv,xpub,prv1,pub1,prv2,pub2,prv3,pub3=main(value)
    bitSeed= byte_to_bit(seed)
    bitEntropy=byte_to_bit(entropy)
    viewer(bitEntropy,mnemonic,bitSeed,bip32,xprv,xpub,prv1,pub1,prv2,pub2,prv3,pub3)
    return

#After the clean button clicked
def clean():
    bitEntropy=""
    mnemonic=""
    bitSeed=""
    xprv=""
    bip32=""
    xpub=""
    xprv=""
    prv1=""
    pub1=""
    prv2=""
    pub2=""
    prv3=""
    pub3=""
    viewer(bitEntropy,mnemonic,bitSeed,bip32,xprv,xpub,prv1,pub1,prv2,pub2,prv3,pub3)
    return
#The generate button 
button1 = tk.Button(text='Generate the seed', command=compute, bg='green', fg='white', font=('helvetica', 9, 'bold'))
canvas1.create_window(400, 150, window=button1)

#the clean button 
button2 = tk.Button(text='Clean', command=clean, bg='red', fg='white', font=('helvetica', 9, 'bold'))
canvas1.create_window(500, 150, window=button2)


root.mainloop()












# main()


# root = Tk()
# frm = ttk.Frame(root, padding=20)
# frm.grid()
# ttk.Label(frm, text="Experiment").grid( row=0)
# canvas1 = ttk.Canvas(root, width=400, height=300)
# canvas1.pack()
# entry1 = ttk.Entry(root)

# ttk.Button(frm, text="Generate Entropy", command=main).grid(column=0, row=1)
# ttk.Button(frm, text="Generate Mnemonic", command=print(entry1)).grid(column=0, row=2)

# ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=2)
# root.mainloop()




















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





